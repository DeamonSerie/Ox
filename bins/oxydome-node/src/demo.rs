//! Self-contained demo: boot a full master + server-node network in-process and run `blocks`
//! consensus rounds, printing the header chain as it finalizes.

use anyhow::Result;
use oxydome_audit::AuditAttestation;
use oxydome_consensus::{MasterCheck, QuorumCertificate, Vote, VoteKind};
use oxydome_master::MasterNode;
use oxydome_node::{default_config, reference_manifest, Node};
use oxydome_state::{ChainState, LedgerStore};

pub fn run(blocks: u64, supply: u128, db: Option<String>) -> Result<()> {
    let config = default_config(4, 4, supply);
    let genesis_cfg = config.genesis()?;
    let params = genesis_cfg.params.clone();
    let (_, genesis, gov) = ChainState::genesis(&genesis_cfg)?;

    let manifest = reference_manifest();
    let root = manifest.root();
    let approved = config.approved_manifest_roots()?;
    if !approved.contains(&root) {
        anyhow::bail!("reference manifest is not in the approved list");
    }

    let master_keys = config
        .masters
        .iter()
        .map(|m| m.keypair().map_err(anyhow::Error::from))
        .collect::<Result<Vec<_>, _>>()?;
    let node_keys = config
        .nodes
        .iter()
        .map(|n| n.keypair().map_err(anyhow::Error::from))
        .collect::<Result<Vec<_>, _>>()?;

    let mut masters: Vec<MasterNode> = master_keys
        .iter()
        .map(|k| {
            let mut m = MasterNode::new(k.clone(), gov.clone(), params.clone(), &genesis);
            for r in &approved {
                m.registry.approve_manifest(*r);
            }
            m
        })
        .collect();

    let mut nodes: Vec<Node> = Vec::new();
    for (i, k) in node_keys.iter().enumerate() {
        let cert = masters[0]
            .handle_admission(k.public(), root, 0)
            .map_err(anyhow::Error::msg)?;
        let (mut node, _genesis) = Node::new(k.clone(), &genesis_cfg, Some(cert))?;
        let mut store = match &db {
            Some(base) => {
                let path = std::path::PathBuf::from(format!("{base}-{i}"));
                node = node.with_content_store(&path.join("assets"))?;
                LedgerStore::open(&path)?
            }
            None => LedgerStore::open_temporary()?,
        };
        store.init_genesis_with_block(&genesis, &node.state.utxo, &node.state.contracts)?;
        nodes.push(node.with_store(store));
    }

    println!("# height  supply          value   gen  state_root");
    println!(
        "{:>6}  {:>12}  {:>7}  {:>3}  {}",
        0,
        genesis.header.supply,
        genesis.header.value_index.to_display(),
        genesis.header.generation,
        genesis.header.state_root.to_hex(),
    );

    for h in 1..=blocks {
        let leader = nodes[0].leader_for(h).unwrap();
        let li = nodes.iter().position(|n| n.public() == leader).unwrap();
        let block = nodes[li].produce_block(h)?;
        let package = nodes[li].audit_package(&block)?;

        let attestations: Vec<AuditAttestation> = masters
            .iter()
            .map(|m| m.audit(&package))
            .collect::<Result<Vec<_>, _>>()?;

        let prepare: Vec<Vote> = nodes
            .iter()
            .map(|n| {
                n.vote(&block, VoteKind::Prepare)
                    .expect("valid prepare block")
            })
            .collect();
        let prepare_qc = QuorumCertificate::new(h, 0, block.hash(), VoteKind::Prepare, prepare);
        let commit: Vec<Vote> = nodes
            .iter()
            .map(|n| {
                n.vote(&block, VoteKind::Commit)
                    .expect("valid commit block")
            })
            .collect();
        let commit_qc = QuorumCertificate::new(h, 0, block.hash(), VoteKind::Commit, commit);
        assert!(prepare_qc.has_quorum(&gov, &params));
        assert!(commit_qc.has_quorum(&gov, &params));

        let checks: Vec<MasterCheck> = nodes.iter().map(|n| n.master_check()).collect();
        for n in &mut nodes {
            n.finalize_block(
                block.clone(),
                &attestations,
                &prepare_qc,
                &commit_qc,
                &checks,
            )?;
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
        for m in &mut masters {
            m.on_finalized(&finalized).map_err(anyhow::Error::msg)?;
        }

        println!(
            "{:>6}  {:>12}  {:>7}  {:>3}  {}",
            h,
            block.header.supply,
            block.header.value_index.to_display(),
            block.header.generation,
            block.header.state_root.to_hex(),
        );
        assert_eq!(
            nodes[0].state.utxo.total(),
            nodes[0].state.supply,
            "lineage invariant"
        );
    }

    let n = &nodes[0];
    println!(
        "\nfinalized: height {}, head {}, supply {}, value {}, state_root {}",
        n.state.height,
        n.state.block_hash.to_hex(),
        n.state.supply,
        n.state.value_index.to_display(),
        n.state.state_root().to_hex(),
    );
    let store = n.store.as_ref().expect("store attached");
    let verified = store.verify_history()?;
    let persisted = store.load_current()?.expect("current version present");
    assert_eq!(
        persisted.root(),
        n.state.utxo_root(),
        "persisted UTXO root must match in-memory UTXO root"
    );
    assert_eq!(persisted.total(), n.state.utxo.total());
    let genesis_root = store.load_ledger(0)?.root();
    assert_eq!(
        genesis_root, genesis.header.utxo_root,
        "height-0 UTXO snapshot must match genesis"
    );
    println!(
        "ledger store: {verified} versions verified through height {}, current root matches in-memory state",
        n.state.height
    );
    println!(
        "all {} nodes agree; lineage sum(UTXO) == supply holds",
        nodes.len()
    );
    Ok(())
}
