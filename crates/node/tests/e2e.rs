//! End-to-end network test: admission, PoA block production, master auditing, BFT +
//! `MasterCheck` finalization, and governed mint/burn/withdraw operations.

use oxydome_audit::AuditAttestation;
use oxydome_consensus::{MasterCheck, QuorumCertificate, Vote, VoteKind};
use oxydome_core::{
    Block, ChainParams, GenesisAllocation, GenesisConfig, GovernanceSet, Operation, OutPoint,
    PublicKey, Transaction, TxOutput,
};
use oxydome_crypto::{CodeManifest, Hash, KeyPair};
use oxydome_master::MasterNode;
use oxydome_net::Message;
use oxydome_node::Node;
use oxydome_rewards::{approve_withdraw, sign_withdraw, withdraw_proposal};
use oxydome_state::{ChainState, LedgerStore, UtxoLedger};
use oxydome_treasury::{approve_burn, approve_mint, burn_proposal, mint_proposal, sign_burn};

const SUPPLY: u128 = 1_000_000_000;

struct World {
    params: ChainParams,
    gov: GovernanceSet,
    nodes: Vec<Node>,
    masters: Vec<MasterNode>,
    node_keys: Vec<KeyPair>,
    master_keys: Vec<KeyPair>,
    user: KeyPair,
    genesis: Block,
}

fn params() -> ChainParams {
    let mut p = ChainParams::default_local();
    p.genesis_supply = SUPPLY;
    p.block_window = 10;
    p.rebound_lock_blocks = 3;
    // Relax the supply-change cap so the tests can mint/burn visible amounts.
    p.supply_change_limit_bps = 1000;
    p
}

fn setup() -> World {
    let params = params();
    let master_keys: Vec<KeyPair> = (1..=4u8).map(|i| KeyPair::from_seed(&[i; 32])).collect();
    let node_keys: Vec<KeyPair> = (11..=14u8).map(|i| KeyPair::from_seed(&[i; 32])).collect();
    let user = KeyPair::from_seed(&[99u8; 32]);

    let masters: Vec<PublicKey> = master_keys.iter().map(|k| k.public()).collect();
    let nodes_pub: Vec<PublicKey> = node_keys.iter().map(|k| k.public()).collect();
    let gov = GovernanceSet::new(masters.clone(), nodes_pub.clone());

    let per_node = 1_000_000u128;
    let mut allocations = Vec::new();
    for n in &nodes_pub {
        allocations.push(GenesisAllocation {
            recipient: *n,
            amount: per_node,
        });
    }
    allocations.push(GenesisAllocation {
        recipient: user.public(),
        amount: SUPPLY - per_node * nodes_pub.len() as u128,
    });

    let config = GenesisConfig {
        params: params.clone(),
        allocations,
        masters: masters.clone(),
        nodes: nodes_pub.clone(),
        timestamp: 0,
    };

    let (_, genesis, _) = ChainState::genesis(&config).unwrap();

    // Approve the node software and admit all nodes.
    let manifest = CodeManifest::from_files(vec![(
        "oxydome-node".to_string(),
        b"reference-node-binary".to_vec(),
    )]);
    let root = manifest.root();

    let mut master_nodes: Vec<MasterNode> = master_keys
        .iter()
        .map(|k| {
            let mut m = MasterNode::new(k.clone(), gov.clone(), params.clone(), &genesis);
            m.registry.approve_manifest(root);
            m
        })
        .collect();

    let mut nodes = Vec::new();
    for k in &node_keys {
        let cert = master_nodes[0]
            .handle_admission(k.public(), root, 0)
            .expect("admission must be granted for approved software");
        let (node, _g) = Node::new(k.clone(), &config, Some(cert)).unwrap();
        let mut store = LedgerStore::open_temporary().unwrap();
        store
            .init_genesis(genesis.hash(), &node.state.utxo)
            .unwrap();
        nodes.push(node.with_store(store));
    }

    World {
        params,
        gov,
        nodes,
        masters: master_nodes,
        node_keys,
        master_keys,
        user,
        genesis,
    }
}

#[test]
fn node_refuses_to_vote_for_an_invalid_state_transition() {
    let world = setup();
    let node = &world.nodes[0];
    let mut block = node
        .state
        .build_block(
            &world.gov,
            &world.params,
            Vec::new(),
            Vec::new(),
            node.public(),
            1,
        )
        .unwrap();
    block.header.state_root = Hash::zero();
    assert!(node.vote(&block, VoteKind::Prepare).is_err());
}

/// Runs one full consensus round at `height`.
#[allow(clippy::too_many_arguments)]
fn advance(w: &mut World, height: u64, txs: Vec<Transaction>, ops: Vec<Operation>) -> Block {
    let leader = w.nodes[0].leader_for(height).unwrap();
    let li = w.nodes.iter().position(|n| n.public() == leader).unwrap();
    for tx in txs {
        w.nodes[li].submit_transaction(tx).unwrap();
    }
    for op in ops {
        w.nodes[li].submit_operation(op).unwrap();
    }

    let block = w.nodes[li].produce_block(height).unwrap();
    let package = w.nodes[li].audit_package(&block).unwrap();

    // Every master audits the package and signs an attestation.
    let attestations: Vec<AuditAttestation> = w
        .masters
        .iter()
        .map(|m| m.audit(&package).expect("master audit must succeed"))
        .collect();
    assert!(
        attestations.len() >= w.gov.master_threshold(&w.params),
        "not enough master attestations"
    );

    // All server nodes vote prepare then commit.
    let prepare_votes: Vec<Vote> = w
        .nodes
        .iter()
        .map(|n| n.vote(&block, VoteKind::Prepare).unwrap())
        .collect();
    let prepare_qc =
        QuorumCertificate::new(height, 0, block.hash(), VoteKind::Prepare, prepare_votes);
    assert!(prepare_qc.has_quorum(&w.gov, &w.params));

    let commit_votes: Vec<Vote> = w
        .nodes
        .iter()
        .map(|n| n.vote(&block, VoteKind::Commit).unwrap())
        .collect();
    let commit_qc = QuorumCertificate::new(height, 0, block.hash(), VoteKind::Commit, commit_votes);
    assert!(commit_qc.has_quorum(&w.gov, &w.params));

    let checks: Vec<MasterCheck> = w.nodes.iter().map(|n| n.master_check()).collect();

    for n in &mut w.nodes {
        n.finalize_block(
            block.clone(),
            &attestations,
            &prepare_qc,
            &commit_qc,
            &checks,
        )
        .expect("finalization must succeed");
    }
    let finalized = oxydome_net::FinalizedBlockRecord {
        block: block.clone(),
        evidence: oxydome_net::FinalityEvidence {
            attestations: attestations.clone(),
            prepare_qc,
            commit_qc,
            master_checks: checks,
        },
    };
    for m in &mut w.masters {
        m.on_finalized(&finalized).unwrap();
    }
    block
}

fn assert_consistent(w: &World) {
    let head = w.nodes[0].state.block_hash;
    for n in &w.nodes {
        assert_eq!(n.state.block_hash, head, "nodes disagree on head");
        assert_eq!(n.state.utxo.total(), n.state.supply, "lineage broken");
    }
}

#[test]
fn end_to_end_blocks_and_governance() {
    let mut w = setup();
    assert_eq!(w.gov.master_threshold(&w.params), 3);
    assert_eq!(w.gov.node_threshold(&w.params), 3);

    // ---- Block 1: a user payment, generating fees and reward outputs. ----
    let (user_out, user_amount) = w.nodes[0].find_spendable(&w.user.public()).unwrap();
    let to_node = 1_000u128;
    let utxo = oxydome_wallet::coinselect::Utxo {
        outpoint: user_out,
        owner: w.user.public(),
        amount: user_amount,
    };
    let mut tx = oxydome_wallet::builder::build_and_sign_local(
        w.user.public(),
        w.node_keys[0].public(),
        to_node,
        std::slice::from_ref(&utxo),
        &w.user,
    )
    .expect("fee-compliant transfer builds and signs");
    let txid = tx.txid();
    let change_outpoint = OutPoint::new(txid, 1);
    let b1 = advance(&mut w, 1, vec![tx], vec![]);
    assert_eq!(b1.header.tx_count, 1);
    assert_consistent(&w);
    // The GAS model converts `gas_server_fee_bps` of each server reward: that Ox is burned and
    // an equal amount of GAS is minted, so a fee-bearing block shrinks the Ox supply by exactly
    // the GAS minted (the master audit recomputes this same figure).
    let supply_after_fees = w.nodes[0].state.supply;
    assert!(
        supply_after_fees < SUPPLY,
        "GAS conversion burns a share of server fees"
    );
    assert_eq!(
        w.nodes[0].state.gas_supply,
        SUPPLY - supply_after_fees,
        "burned Ox must equal minted GAS"
    );

    // ---- Block 2: governed mint. ----
    let mint_amount = 5_000u128;
    let mut mint = mint_proposal(mint_amount, w.user.public());
    for k in w.master_keys.iter().take(3) {
        approve_mint(&mut mint, k);
    }
    advance(&mut w, 2, vec![], vec![Operation::Mint(mint)]);
    assert_consistent(&w);
    assert_eq!(
        w.nodes[0].state.supply,
        supply_after_fees + mint_amount
    );
    assert_eq!(w.nodes[0].state.epoch_minted, mint_amount);

    // ---- Block 3: governed burn from the user's change output. ----
    let burn_amount = 500u128;
    let mut burn = burn_proposal(change_outpoint, w.user.public(), burn_amount);
    sign_burn(&mut burn, &w.user);
    for k in w.master_keys.iter().take(3) {
        approve_burn(&mut burn, k);
    }
    advance(&mut w, 3, vec![], vec![Operation::Burn(burn)]);
    assert_consistent(&w);
    assert_eq!(
        w.nodes[0].state.supply,
        supply_after_fees + mint_amount - burn_amount
    );

    // ---- Block 4: governed node withdrawal of locked fee earnings. ----
    let (node_index, locked_input, locked_amount) = find_locked_reward(&w).unwrap();
    let withdraw_amount = locked_amount.min(100);
    let node_key = w.node_keys[node_index].clone();
    let mut withdraw = withdraw_proposal(node_key.public(), vec![locked_input], withdraw_amount);
    sign_withdraw(&mut withdraw, &node_key);
    let mut approvers = 0;
    for (i, k) in w.node_keys.iter().enumerate() {
        if i != node_index {
            approve_withdraw(&mut withdraw, k);
            approvers += 1;
        }
        if approvers >= 3 {
            break;
        }
    }
    advance(&mut w, 4, vec![], vec![Operation::Withdraw(withdraw)]);
    assert_consistent(&w);

    // The node now holds spendable Ox unlocked from the reward.
    let spendable = w.nodes[0]
        .state
        .utxo
        .iter()
        .any(|e| e.output.recipient == node_key.public() && e.output.kind.is_spendable());
    assert!(spendable, "withdrawal should unlock spendable Ox");

    // ---- Ledger store: every version persisted, current root matches state, and the
    //      genesis allocation remains provable against the height-0 snapshot. ----
    for n in &w.nodes {
        let store = n.store.as_ref().unwrap();
        assert_eq!(
            store.verify_history().unwrap(),
            n.state.height as usize + 1,
            "every finalized version must verify"
        );
        let current = store.load_current().unwrap().unwrap();
        assert_eq!(
            current.root(),
            n.state.utxo_root(),
            "persisted root mismatch"
        );
        assert_eq!(
            current.total(),
            n.state.utxo.total(),
            "persisted total mismatch"
        );
    }

    let g0 = w.nodes[0].store.as_ref().unwrap().load_ledger(0).unwrap();
    assert_eq!(
        g0.root(),
        w.genesis.header.state_root,
        "genesis snapshot must commit the genesis state root"
    );
    let (user_op, user_entry) = g0
        .iter()
        .find_map(|e| {
            if e.output.recipient == w.user.public() {
                Some((e.outpoint, e.clone()))
            } else {
                None
            }
        })
        .expect("user genesis allocation present in snapshot");
    let proof = g0.proof(&user_op).unwrap();
    assert!(UtxoLedger::verify_inclusion(
        &g0.root(),
        &user_entry,
        &proof
    ));

    // Even though the user spent from the allocation, an older version keeps it intact.
    assert!(
        w.nodes[0].state.utxo.get(&user_op).is_none(),
        "spent genesis output must be gone from the current ledger"
    );

    // ---- Rejection paths ----
    // Unapproved software is not admitted.
    let bogus = CodeManifest::from_files(vec![("evil".to_string(), b"malware".to_vec())]);
    assert!(w.masters[0]
        .handle_admission(w.user.public(), bogus.root(), 0)
        .is_err());

    // An already-spent input cannot be packaged against the current tip.
    assert!(w.nodes[0].audit_package(&b1).is_err());

    // A tampered package fails the master audit.
    let leader = w.nodes[0].leader_for(w.nodes[0].next_height()).unwrap();
    let li = w.nodes.iter().position(|n| n.public() == leader).unwrap();
    let fresh = w.nodes[li].produce_block(100).unwrap();
    let mut tampered_pkg = w.nodes[0].audit_package(&fresh).unwrap();
    tampered_pkg.pre_utxo_root = Hash::zero();
    assert!(w.masters[0].audit(&tampered_pkg).is_err());
}

fn find_locked_reward(w: &World) -> Option<(usize, OutPoint, u128)> {
    for (i, n) in w.nodes.iter().enumerate() {
        let owner = n.public();
        if let Some(e) = n
            .state
            .utxo
            .iter()
            .find(|e| e.output.kind.is_locked_reward() && e.output.recipient == owner)
        {
            return Some((i, e.outpoint, e.output.amount));
        }
    }
    None
}

#[test]
fn message_wire_round_trips() {
    let msg = Message::Ping { nonce: 42 };
    let bytes = oxydome_net::encode_message(&msg).unwrap();
    match oxydome_net::decode_message(&bytes).unwrap() {
        Message::Ping { nonce } => assert_eq!(nonce, 42),
        _ => panic!("wrong message"),
    }

    let msg = Message::CallOvmContract {
        contract_id: Hash([1; 64]),
        entry_point: "balanceOf".into(),
        arguments: vec![7],
        caller: PublicKey::from_bytes([2; 32]),
        gas_limit: 1_000,
    };
    let bytes = oxydome_net::encode_message(&msg).unwrap();
    match oxydome_net::decode_message(&bytes).unwrap() {
        Message::CallOvmContract {
            contract_id,
            entry_point,
            arguments,
            caller,
            gas_limit,
        } => {
            assert_eq!(contract_id, Hash([1; 64]));
            assert_eq!(entry_point, "balanceOf");
            assert_eq!(arguments, vec![7]);
            assert_eq!(caller, PublicKey::from_bytes([2; 32]));
            assert_eq!(gas_limit, 1_000);
        }
        _ => panic!("wrong message"),
    }

    let content = b"non-consensus app content".to_vec();
    let msg = Message::StoreContent {
        hash: oxydome_ovm::content_hash(&content),
        content: content.clone(),
    };
    let bytes = oxydome_net::encode_message(&msg).unwrap();
    match oxydome_net::decode_message(&bytes).unwrap() {
        Message::StoreContent {
            hash,
            content: data,
        } => {
            assert_eq!(hash, oxydome_ovm::content_hash(&content));
            assert_eq!(data, content);
        }
        _ => panic!("wrong message"),
    }

    let msg = Message::GetContent {
        hash: oxydome_ovm::content_hash(&content),
        hops_remaining: 4,
    };
    let bytes = oxydome_net::encode_message(&msg).unwrap();
    match oxydome_net::decode_message(&bytes).unwrap() {
        Message::GetContent {
            hash,
            hops_remaining,
        } => {
            assert_eq!(hash, oxydome_ovm::content_hash(&content));
            assert_eq!(hops_remaining, 4);
        }
        _ => panic!("wrong message"),
    }
}
