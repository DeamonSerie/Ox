//! Async TCP server and client helpers for a server node.
//!
//! The server handles liveness, chain synchronisation and admission responses. Consensus
//! rounds are driven by [`crate::sim`], which exchanges the same [`oxydome_net::Message`]
//! values between nodes; this keeps the wire format identical whether the messages travel
//! over a socket or through the in-process simulation.

use crate::Node;
use oxydome_consensus::AdmissionCertificate;
use oxydome_core::{
    Amount, Block, Hash, InboundReceipt, OhmBlock, OhmState, OutPoint, OutboundMessage, PublicKey,
    Transaction,
};
use oxydome_crypto::SparseProof;
use oxydome_net::{
    recv_message, send_message, BalanceInfo, HistoryEntry, Message, NetError, NodeEvent,
    TxLocation, TxStatus, UtxoInfo, ValueIndexInfo, WalletSubscription,
};
use oxydome_state::UtxoEntry;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;

const MAX_CONTENT_FORWARD_HOPS: u8 = 4;

/// Shared node handle for the async server.
pub type SharedNode = Arc<Mutex<Node>>;

/// Runs the node accept loop until the process exits.
pub async fn run(addr: &str, node: Node) -> std::io::Result<SocketAddr> {
    run_with_peers(addr, node, Vec::new()).await
}

/// Runs the node accept loop with peers for authenticated block sync and optional asset retrieval.
pub async fn run_with_peers(
    addr: &str,
    node: Node,
    peers: Vec<SocketAddr>,
) -> std::io::Result<SocketAddr> {
    let listener = TcpListener::bind(addr).await?;
    let _local = listener.local_addr()?;
    let shared: SharedNode = Arc::new(Mutex::new(node));
    let peers = Arc::new(peers);
    loop {
        let (stream, _peer) = listener.accept().await?;
        let shared = Arc::clone(&shared);
        let peers = Arc::clone(&peers);
        tokio::spawn(async move {
            let _ = handle_connection(stream, shared, peers).await;
        });
    }
}

/// Binds a listener and spawns the accept loop, returning the bound address.
pub async fn run_server(addr: &str, node: Node) -> std::io::Result<SocketAddr> {
    let (addr, _shared) = run_server_with_handle(addr, node).await?;
    Ok(addr)
}

/// Binds a listener and spawns the accept loop, returning the bound address and the shared
/// node handle so callers (for example integration tests) can drive consensus in-process
/// while wallet clients talk over the wire.
pub async fn run_server_with_handle(
    addr: &str,
    node: Node,
) -> std::io::Result<(SocketAddr, SharedNode)> {
    run_server_with_peers_and_handle(addr, node, Vec::new()).await
}

/// Test/embedded-server variant of [`run_server_with_handle`] with static content peers.
pub async fn run_server_with_peers_and_handle(
    addr: &str,
    node: Node,
    peers: Vec<SocketAddr>,
) -> std::io::Result<(SocketAddr, SharedNode)> {
    let listener = TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    let shared: SharedNode = Arc::new(Mutex::new(node));
    let accept_shared = Arc::clone(&shared);
    let peers = Arc::new(peers);
    tokio::spawn(async move {
        loop {
            let (stream, _peer) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(_) => return,
            };
            let shared = Arc::clone(&accept_shared);
            let peers = Arc::clone(&peers);
            tokio::spawn(async move {
                let _ = handle_connection(stream, shared, peers).await;
            });
        }
    });
    Ok((local, shared))
}

async fn handle_connection(
    mut stream: TcpStream,
    node: SharedNode,
    peers: Arc<Vec<SocketAddr>>,
) -> std::io::Result<()> {
    loop {
        let msg = match recv_message(&mut stream).await {
            Ok(m) => m,
            Err(_) => return Ok(()),
        };
        // Build the reply without holding the lock across an await.
        let reply: Option<Message> = match msg {
            Message::Ping { nonce } => Some(Message::Pong { nonce }),
            Message::GetHeaders { from_height } => {
                let blocks = {
                    let guard = node.lock().unwrap();
                    guard
                        .blocks
                        .iter()
                        .filter(|b| b.header.height >= from_height)
                        .cloned()
                        .collect()
                };
                Some(Message::HeadersResponse { blocks })
            }
            Message::GetFinalizedBlocks { from_height, limit } => {
                let guard = node.lock().unwrap();
                let tip_height = guard.state.height;
                let result = guard.finalized_blocks_from(from_height, limit);
                Some(match result {
                    Ok(blocks) => Message::FinalizedBlocksResponse {
                        blocks,
                        tip_height,
                        error: None,
                    },
                    Err(error) => Message::FinalizedBlocksResponse {
                        blocks: Vec::new(),
                        tip_height,
                        error: Some(error),
                    },
                })
            }
            Message::GetBalance { owner } => {
                let info = {
                    let guard = node.lock().unwrap();
                    guard.balance(&owner)
                };
                Some(Message::BalanceResponse { info })
            }
            Message::GetUtxos { owner } => {
                let entries = {
                    let guard = node.lock().unwrap();
                    guard.utxos(&owner)
                };
                Some(Message::UtxosResponse { entries })
            }
            Message::GetUtxoProof { outpoint } => {
                let (entry, proof) = {
                    let guard = node.lock().unwrap();
                    guard.utxo_proof(&outpoint)
                };
                Some(Message::UtxoProofResponse { entry, proof })
            }
            Message::GetBlockByHeight { height } => {
                let block = {
                    let guard = node.lock().unwrap();
                    guard.block_by_height(height)
                };
                Some(Message::BlockByHeightResponse {
                    block: block.map(Box::new),
                })
            }
            Message::GetTransaction { txid } => {
                let (tx, location, status) = {
                    let guard = node.lock().unwrap();
                    guard.transaction(&txid)
                };
                Some(Message::TransactionResponse {
                    tx: tx.map(Box::new),
                    location,
                    status,
                })
            }
            Message::GetHistory {
                owner,
                cursor,
                limit,
            } => {
                let (entries, next_cursor) = {
                    let guard = node.lock().unwrap();
                    guard.history(&owner, cursor, limit)
                };
                Some(Message::HistoryResponse {
                    entries,
                    next_cursor,
                })
            }
            Message::GetValueIndex => {
                let info = {
                    let guard = node.lock().unwrap();
                    guard.value_index()
                };
                Some(Message::ValueIndexResponse { info })
            }
            Message::SubmitTransaction { tx } => {
                let txid = tx.txid();
                let accepted = { node.lock().unwrap().submit_transaction(*tx) };
                let (accepted, error) = match accepted {
                    Ok(()) => (true, None),
                    Err(e) => (false, Some(e.to_string())),
                };
                Some(Message::SubmitResponse {
                    txid,
                    accepted,
                    error,
                })
            }
            Message::SubmitOperation { operation } => {
                let operation_id = operation.id();
                let result = node.lock().unwrap().submit_operation(*operation);
                let (accepted, error) = match result {
                    Ok(()) => (true, None),
                    Err(error) => (false, Some(error.to_string())),
                };
                Some(Message::OperationSubmitResponse {
                    operation_id,
                    accepted,
                    error,
                })
            }
            Message::GetDao { dao_id } => {
                let state = node.lock().unwrap().state.daos.get(&dao_id).cloned();
                Some(Message::DaoResponse { dao_id, state })
            }
            Message::GetOhm { ohm_id } => {
                let state = node.lock().unwrap().ohm_state(&ohm_id).cloned();
                Some(Message::OhmResponse {
                    ohm_id,
                    state: state.map(Box::new),
                })
            }
            Message::GetOhmBlock { hash } => {
                let block = node.lock().unwrap().ohm_block(&hash).cloned();
                Some(Message::OhmBlockResponse {
                    block: block.map(Box::new),
                })
            }
            Message::GetOhmBalance { ohm_id, owner } => {
                let amount = {
                    let guard = node.lock().unwrap();
                    guard
                        .ohm_ledger(&ohm_id)
                        .map(|ledger| {
                            ledger
                                .utxos
                                .values()
                                .filter(|entry| entry.output.recipient == owner)
                                .map(|entry| entry.output.amount)
                                .sum()
                        })
                        .unwrap_or(0)
                };
                Some(Message::OhmBalanceResponse { ohm_id, amount })
            }
            Message::SubmitOhmBlock { block } => {
                let hash = block.hash();
                let result = node.lock().unwrap().submit_ohm_block(*block);
                let (accepted, error) = match result {
                    Ok(_) => (true, None),
                    Err(error) => (false, Some(error.to_string())),
                };
                Some(Message::OhmBlockSubmitResponse {
                    hash,
                    accepted,
                    error,
                })
            }
            Message::GetOhmContract {
                ohm_id,
                contract_id,
            } => {
                let contract = node
                    .lock()
                    .unwrap()
                    .ohm_contract(&ohm_id, &contract_id)
                    .cloned();
                let (code, storage) = match contract {
                    Some(contract) => {
                        let storage = contract.storage.into_iter().collect();
                        (Some(contract.code), Some(storage))
                    }
                    None => (None, None),
                };
                Some(Message::OhmContractResponse {
                    ohm_id,
                    contract_id,
                    code,
                    storage,
                })
            }
            Message::GetGasBalance { owner } => {
                let amount = {
                    let guard = node.lock().unwrap();
                    guard.gas_balance(&owner)
                };
                Some(Message::GasBalanceResponse { amount })
            }
            Message::GetGasSupply => {
                let amount = {
                    let guard = node.lock().unwrap();
                    guard.gas_supply()
                };
                Some(Message::GasSupplyResponse { amount })
            }
            Message::GetGasPrice => {
                let amount = {
                    let guard = node.lock().unwrap();
                    guard.gas_price()
                };
                Some(Message::GasPriceResponse {})
            }
            Message::GetGasAirdropInfo => {
                let height = {
                    let guard = node.lock().unwrap();
                    guard.last_airdrop_height()
                };
                Some(Message::GasAirdropInfoResponse { height })
            }
            Message::CallOhmContract {
                ohm_id,
                contract_id,
                entry_point,
                arguments,
                caller,
                gas_limit,
            } => {
                let result = node.lock().unwrap().ohm_call_contract(
                    &ohm_id,
                    &contract_id,
                    &entry_point,
                    caller,
                    &arguments,
                    gas_limit,
                );
                match result {
                    Ok(outcome) => Some(Message::OhmContractCallResponse {
                        failure: outcome.failure,
                        gas_used: outcome.gas_used,
                        return_value: outcome.return_value,
                        logs: outcome
                            .logs
                            .into_iter()
                            .map(|log| oxydome_core::OvmLog {
                                topic: log.topic,
                                value: log.value,
                            })
                            .collect(),
                        error: None,
                    }),
                    Err(error) => Some(Message::OhmContractCallResponse {
                        failure: None,
                        gas_used: 0,
                        return_value: None,
                        logs: Vec::new(),
                        error: Some(error.to_string()),
                    }),
                }
            }
            Message::GetOhmOutbox { ohm_id } => {
                let messages = node
                    .lock()
                    .unwrap()
                    .ohm_outbox(&ohm_id)
                    .map(|outbox| outbox.values().cloned().collect())
                    .unwrap_or_default();
                Some(Message::OhmOutboxResponse { ohm_id, messages })
            }
            Message::GetOhmInbox { ohm_id } => {
                let receipts = node
                    .lock()
                    .unwrap()
                    .ohm_inbox(&ohm_id)
                    .map(|inbox| inbox.values().cloned().collect())
                    .unwrap_or_default();
                Some(Message::OhmInboxResponse { ohm_id, receipts })
            }
            Message::GetOvmCode { contract_id } => {
                let code = node.lock().unwrap().ovm_code(&contract_id);
                Some(Message::OvmCodeResponse { code })
            }
            Message::CallOvm {
                contract_id,
                arguments,
                gas_limit,
            } => {
                let result = node
                    .lock()
                    .unwrap()
                    .ovm_call(&contract_id, &arguments, gas_limit);
                let (execution, error) = match result {
                    Ok(execution) => (Some(execution), None),
                    Err(error) => (None, Some(error)),
                };
                Some(Message::OvmCallResponse { execution, error })
            }
            Message::CallOvmContract {
                contract_id,
                entry_point,
                arguments,
                caller,
                gas_limit,
            } => {
                let result = node.lock().unwrap().ovm_contract_call(
                    &contract_id,
                    &entry_point,
                    &arguments,
                    caller,
                    gas_limit,
                );
                let (execution, error) = match result {
                    Ok(execution) => (Some(execution), None),
                    Err(error) => (None, Some(error)),
                };
                Some(Message::OvmContractCallResponse { execution, error })
            }
            Message::GetContent {
                hash,
                hops_remaining,
            } => {
                let local = node.lock().unwrap().get_content(&hash);
                let hops_remaining = hops_remaining.min(MAX_CONTENT_FORWARD_HOPS);
                let content = if local.is_some() || hops_remaining == 0 {
                    local
                } else {
                    fetch_content_from_peers(&peers, hash, hops_remaining - 1).await
                };
                Some(Message::ContentResponse { content })
            }
            Message::StoreContent { hash, content } => {
                let result = node.lock().unwrap().put_content(hash, content);
                let (stored, error) = match result {
                    Ok(()) => (true, None),
                    Err(error) => (false, Some(error)),
                };
                Some(Message::StoreContentResponse { stored, error })
            }
            Message::GetFileLabel {
                key_chain_commitment,
            } => {
                let label = {
                    let guard = node.lock().unwrap();
                    guard.state.file_labels.get(&key_chain_commitment).cloned()
                };
                Some(Message::FileLabelResponse { label })
            }
            Message::GetFileAccessLog { file_id } => {
                let records = {
                    let guard = node.lock().unwrap();
                    guard
                        .state
                        .file_access_log
                        .values()
                        .filter(|r| r.file_id == file_id)
                        .cloned()
                        .collect()
                };
                Some(Message::FileAccessLogResponse { records })
            }
            Message::GetNodeFileRoot { .. } => {
                let (file_root, file_count, file_storage_bytes) = {
                    let guard = node.lock().unwrap();
                    guard.node_file_root()
                };
                Some(Message::NodeFileRootResponse {
                    file_root,
                    file_count,
                    file_storage_bytes,
                })
            }
            Message::FinalizedBlock { finalized } => {
                // Clone state for async transaction pre-validation so no mutex guard
                // is held across the await point.
                let (state_clone, params_clone, record_clone) = {
                    let guard = node.lock().unwrap();
                    (guard.state.clone(), guard.params.clone(), finalized.clone())
                };
                let node_ref = node.clone();
                tokio::spawn(async move {
                    let block_clone = &record_clone.block;
                    let evidence_clone = &record_clone.evidence;
                    // filter_sync runs on a smol blocking thread via filter_invalid_transactions,
                    // so the tokio worker is never blocked by CPU-bound validation.
                    let (valid_txs, _stats, filtered_count) =
                        oxydome_state::async_verify::filter_invalid_transactions(
                            &state_clone,
                            block_clone,
                            &params_clone,
                        )
                        .await;
                    let block_to_finalize = if filtered_count > 0 {
                        oxydome_state::async_verify::rebuild_block(block_clone, valid_txs, &params_clone)
                    } else {
                        block_clone.clone()
                    };
                    let mut guard = node_ref.lock().unwrap();
                    if let Err(error) = guard.finalize_block(
                        block_to_finalize,
                        &evidence_clone.attestations,
                        &evidence_clone.prepare_qc,
                        &evidence_clone.commit_qc,
                        &evidence_clone.master_checks,
                    ) {
                        eprintln!("rejected finalized peer block: {error}");
                    }
                });
                None
            }
            Message::Subscribe { kinds } => {
                let rx = { node.lock().unwrap().events.subscribe() };
                send_message(
                    &mut stream,
                    &Message::SubscribeResponse {
                        ok: true,
                        error: None,
                    },
                )
                .await
                .ok();
                stream_events(&mut stream, rx, kinds).await;
                return Ok(());
            }
            Message::AdmitResponse {
                certificate,
                reason,
                ..
            } => {
                if let Some(cert) = certificate {
                    let mut guard = node.lock().unwrap();
                    guard.admission = Some(*cert);
                }
                if let Some(reason) = reason {
                    eprintln!("admission rejected: {reason}");
                }
                None
            }
            Message::StorageLabelRequest { nonce: _ } => {
                let guard = node.lock().unwrap();
                if let Some(labeler) = guard.storage_labeler() {
                    if let Some(label) = labeler.last_label() {
                        Some(Message::StorageLabelResponse { label })
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            _ => None,
        };
        if let Some(reply) = reply {
            send_message(&mut stream, &reply).await.ok();
        }
    }
}

async fn fetch_content_from_peers(
    peers: &[SocketAddr],
    hash: Hash,
    hops_remaining: u8,
) -> Option<Vec<u8>> {
    for peer in peers {
        let result = tokio::time::timeout(Duration::from_secs(2), async {
            let mut stream = TcpStream::connect(peer).await?;
            send_message(
                &mut stream,
                &Message::GetContent {
                    hash,
                    hops_remaining,
                },
            )
            .await?;
            loop {
                match recv_message(&mut stream).await? {
                    Message::ContentResponse { content } => {
                        return Ok::<Option<Vec<u8>>, NetError>(content)
                    }
                    Message::Ping { nonce } => {
                        send_message(&mut stream, &Message::Pong { nonce }).await?;
                    }
                    _ => return Ok::<Option<Vec<u8>>, NetError>(None),
                }
            }
        })
        .await;
        if let Ok(Ok(Some(content))) = result {
            if content.len() as u64 <= oxydome_ovm::MAX_ASSET_BYTES
                && oxydome_ovm::content_hash(&content) == hash
            {
                return Some(content);
            }
        }
    }
    None
}

/// Requests admission from a master and returns the certificate if granted.
pub async fn request_admission(
    master_addr: SocketAddr,
    node: oxydome_core::PublicKey,
    manifest: oxydome_crypto::CodeManifest,
    timestamp: u64,
) -> Result<Option<AdmissionCertificate>, NetError> {
    let mut stream = TcpStream::connect(master_addr).await?;
    let manifest_root = manifest.root();
    send_message(
        &mut stream,
        &Message::AdmitRequest {
            node,
            manifest_root,
            manifest,
            nonce: timestamp,
            timestamp,
            chain_id: None,
        },
    )
    .await
    .ok();
    loop {
        match recv_message(&mut stream).await {
            Ok(Message::AdmitResponse {
                certificate,
                reason,
                ..
            }) => {
                if let Some(reason) = reason {
                    eprintln!("admission rejected: {reason}");
                }
                return Ok(certificate.map(|b| *b));
            }
            Ok(_) => continue,
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxydome_consensus::{QuorumCertificate, VoteKind};
    use oxydome_core::{OvmAction, Transaction, TxOutput};
    use oxydome_master::MasterNode;
    use oxydome_net::{recv_message, send_message};

    #[tokio::test]
    async fn retrieves_content_from_a_configured_peer_without_consensus_state() {
        let config = crate::default_config(1, 1, 100_000);
        let genesis = config.genesis().unwrap();
        let key = config.nodes[0].keypair().unwrap();
        let (mut source, _) = Node::new(key.clone(), &genesis, None).unwrap();
        let bytes = b"static app assets".to_vec();
        let hash = oxydome_ovm::content_hash(&bytes);
        source.put_content(hash, bytes.clone()).unwrap();
        let (source_addr, _) = run_server_with_handle("127.0.0.1:0", source).await.unwrap();

        let (proxy, _) = Node::new(key, &genesis, None).unwrap();
        let (proxy_addr, _) =
            run_server_with_peers_and_handle("127.0.0.1:0", proxy, vec![source_addr])
                .await
                .unwrap();
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        send_message(
            &mut client,
            &Message::GetContent {
                hash,
                hops_remaining: MAX_CONTENT_FORWARD_HOPS,
            },
        )
        .await
        .unwrap();
        match recv_message(&mut client).await.unwrap() {
            Message::ContentResponse {
                content: Some(received),
            } => assert_eq!(received, bytes),
            other => panic!("unexpected content response: {other:?}"),
        }
    }

    async fn finalized_source() -> (
        Node,
        oxydome_core::GenesisConfig,
        oxydome_crypto::KeyPair,
        tempfile::TempDir,
    ) {
        let mut config = crate::default_config(1, 1, 100_000);
        config.params.gas_activation_height = u64::MAX;
        let genesis = config.genesis().unwrap();
        let node_key = config.nodes[0].keypair().unwrap();
        let follower_key = config.nodes[0].keypair().unwrap();
        let (mut node, block_zero) = Node::new(node_key, &genesis, None).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let mut store = oxydome_state::LedgerStore::open(directory.path()).unwrap();
        store
            .init_genesis_with_block(&block_zero, &node.state.utxo, &node.state.contracts)
            .unwrap();
        node = node.with_store(store);
        let master_key = config.masters[0].keypair().unwrap();
        let mut master = MasterNode::new(
            master_key,
            node.gov.clone(),
            node.params.clone(),
            &block_zero,
        );
        for height in 1..=2 {
            if height == 1 {
                let (outpoint, amount) = node
                    .state
                    .utxo
                    .iter()
                    .find(|entry| entry.output.recipient == node.public())
                    .map(|entry| (entry.outpoint, entry.output.amount))
                    .unwrap();
                let program = oxydome_ovm::Program {
                    argument_count: oxydome_ovm::AUTHORITY_WORD_COUNT as u8,
                    local_count: 0,
                    instructions: vec![
                        oxydome_ovm::Instruction::Push(7),
                        oxydome_ovm::Instruction::Return,
                    ],
                }
                .encode()
                .unwrap();
                let artifact = oxydome_ovm::ContractArtifact {
                    source_hash: None,
                    asset_manifest_hash: None,
                    functions: vec![oxydome_ovm::ContractFunction {
                        name: "read".into(),
                        inputs: Vec::new(),
                        output: Some(oxydome_ovm::ContractValueType::U64),
                        code: program,
                    }],
                }
                .encode()
                .unwrap();
                let stack_bytes = 1_000u64;
                let stack_gas = (stack_bytes + 5) / 6;
                let fee = 1 + u128::from(stack_gas);
                let mut deployment = Transaction::new_unsigned(
                    vec![(outpoint, node.public())],
                    vec![TxOutput::spendable(amount - fee, node.public())],
                    fee,
                );
                deployment.ovm_action = Some(OvmAction::DeployContract {
                    artifact,
                    stack_bytes,
                });
                deployment.sign_input(0, &node.key);
                node.submit_transaction(deployment).unwrap();
            }
            let block = node.produce_block(height).unwrap();
            let package = node.audit_package(&block).unwrap();
            let attestations = vec![master.audit(&package).unwrap()];
            let prepare = QuorumCertificate::new(
                height,
                0,
                block.hash(),
                VoteKind::Prepare,
                vec![node.vote(&block, VoteKind::Prepare).unwrap()],
            );
            let commit = QuorumCertificate::new(
                height,
                0,
                block.hash(),
                VoteKind::Commit,
                vec![node.vote(&block, VoteKind::Commit).unwrap()],
            );
            let checks = vec![node.master_check()];
            let finalized = oxydome_net::FinalizedBlockRecord {
                block: block.clone(),
                evidence: oxydome_net::FinalityEvidence {
                    attestations: attestations.clone(),
                    prepare_qc: prepare.clone(),
                    commit_qc: commit.clone(),
                    master_checks: checks.clone(),
                },
            };
            node.finalize_block(block, &attestations, &prepare, &commit, &checks)
                .unwrap();
            master.on_finalized(&finalized).unwrap();
        }
        (node, genesis, follower_key, directory)
    }

    #[tokio::test]
    async fn catches_up_by_verifying_finality_and_replaying_blocks() {
        let (mut source, genesis, follower_key, _directory) = finalized_source().await;
        let expected_root = source.state.state_root();
        let store = source.store.take().unwrap();
        let (restored, _) = Node::new(oxydome_crypto::KeyPair::generate(), &genesis, None).unwrap();
        let restored = restored.restore_from_store(store, None).unwrap();
        let (peer, _) = run_server_with_handle("127.0.0.1:0", restored)
            .await
            .unwrap();
        let (mut follower, _) = Node::new(follower_key, &genesis, None).unwrap();

        assert_eq!(
            catch_up_node_from_peer(&mut follower, peer).await.unwrap(),
            2
        );
        assert_eq!(follower.state.height, 2);
        assert_eq!(follower.state.state_root(), expected_root);
        assert_eq!(follower.blocks.len(), 3);
        assert_eq!(follower.state.contracts.len(), 1);
    }

    #[tokio::test]
    async fn rejects_peer_block_with_forged_quorum_evidence() {
        let (mut source, genesis, follower_key, _directory) = finalized_source().await;
        source
            .finality_evidence
            .get_mut(&1)
            .unwrap()
            .commit_qc
            .votes
            .clear();
        let (peer, _) = run_server_with_handle("127.0.0.1:0", source).await.unwrap();
        let (mut follower, _) = Node::new(follower_key, &genesis, None).unwrap();

        assert!(catch_up_node_from_peer(&mut follower, peer).await.is_err());
        assert_eq!(follower.state.height, 0);
    }
}

/// Fetches unverified block bodies for inspection only.
///
/// Consensus catch-up must use [`fetch_finalized_block`] and verify its evidence.
pub async fn fetch_headers(
    peer: SocketAddr,
    from_height: u64,
) -> Result<Vec<oxydome_core::Block>, NetError> {
    let mut stream = TcpStream::connect(peer).await?;
    send_message(&mut stream, &Message::GetHeaders { from_height })
        .await
        .ok();
    loop {
        match recv_message(&mut stream).await {
            Ok(Message::HeadersResponse { blocks }) => return Ok(blocks),
            Ok(_) => continue,
            Err(e) => return Err(e),
        }
    }
}

/// Fetches one finalized block record with evidence for independent verification.
pub async fn fetch_finalized_block(
    peer: SocketAddr,
    from_height: u64,
) -> Result<(Option<oxydome_net::FinalizedBlockRecord>, u64), NetError> {
    match request(
        peer,
        &Message::GetFinalizedBlocks {
            from_height,
            limit: 1,
        },
    )
    .await?
    {
        Message::FinalizedBlocksResponse {
            mut blocks,
            tip_height,
            error: None,
        } if blocks.len() <= 1 => Ok((blocks.pop(), tip_height)),
        Message::FinalizedBlocksResponse {
            error: Some(error), ..
        } => Err(NetError::Unexpected(error)),
        Message::FinalizedBlocksResponse { .. } => Err(NetError::Unexpected(
            "peer returned more finalized blocks than requested".into(),
        )),
        other => Err(NetError::Unexpected(format!("{other:?}"))),
    }
}

/// Catches a running node up by verifying finality evidence and executing each block locally.
///
/// This returns an error on any missing, malformed, noncontiguous, or invalid certificate. A
/// partially caught-up node retains only blocks that passed full finality and state validation.
pub async fn catch_up_from_peer(node: &SharedNode, peer: SocketAddr) -> Result<usize, NetError> {
    let mut next_height = {
        let guard = node
            .lock()
            .map_err(|_| NetError::Unexpected("node state lock is poisoned".into()))?;
        guard
            .state
            .height
            .checked_add(1)
            .ok_or_else(|| NetError::Unexpected("node height overflow".into()))?
    };
    let mut applied = 0usize;
    loop {
        let (record, tip_height) = fetch_finalized_block(peer, next_height).await?;
        let Some(record) = record else {
            if tip_height >= next_height {
                return Err(NetError::Unexpected(format!(
                    "peer advertises tip {tip_height} but has no finalized block at height {next_height}"
                )));
            }
            break;
        };
        if record.block.header.height != next_height {
            return Err(NetError::Unexpected(format!(
                "peer returned height {} while {} was requested",
                record.block.header.height, next_height
            )));
        }
        let mut guard = node
            .lock()
            .map_err(|_| NetError::Unexpected("node state lock is poisoned".into()))?;
        apply_finalized_record(&mut guard, record)?;
        applied += 1;
        next_height = next_height
            .checked_add(1)
            .ok_or_else(|| NetError::Unexpected("node height overflow".into()))?;
    }
    Ok(applied)
}

/// Catches a node up from one peer before its listener starts.
pub async fn catch_up_node_from_peer(node: &mut Node, peer: SocketAddr) -> Result<usize, NetError> {
    let mut next_height = node
        .state
        .height
        .checked_add(1)
        .ok_or_else(|| NetError::Unexpected("node height overflow".into()))?;
    let mut applied = 0usize;
    loop {
        let (record, tip_height) = fetch_finalized_block(peer, next_height).await?;
        let Some(record) = record else {
            if tip_height >= next_height {
                return Err(NetError::Unexpected(format!(
                    "peer advertises tip {tip_height} but has no finalized block at height {next_height}"
                )));
            }
            break;
        };
        if record.block.header.height != next_height {
            return Err(NetError::Unexpected(format!(
                "peer returned height {} while {} was requested",
                record.block.header.height, next_height
            )));
        }
        apply_finalized_record(node, record)?;
        applied += 1;
        next_height = next_height
            .checked_add(1)
            .ok_or_else(|| NetError::Unexpected("node height overflow".into()))?;
    }
    Ok(applied)
}

fn apply_finalized_record(
    node: &mut Node,
    record: oxydome_net::FinalizedBlockRecord,
) -> Result<(), NetError> {
    // Pre-validate transactions synchronously; rebuild the block if any are invalid.
    let (valid_txs, _stats, filtered_count) = oxydome_state::async_verify::filter_sync(
        &node.state,
        &record.block,
        &node.params,
        record.block.header.height,
    );
    let block = if filtered_count > 0 {
        oxydome_state::async_verify::rebuild_block(&record.block, valid_txs, &node.params)
    } else {
        record.block
    };
    node.finalize_block(
        block,
        &record.evidence.attestations,
        &record.evidence.prepare_qc,
        &record.evidence.commit_qc,
        &record.evidence.master_checks,
    )
    .map_err(|error| NetError::Unexpected(format!("peer block rejected: {error}")))
}

/// Sends a single request and waits for the first non-pong reply.
async fn request(peer: SocketAddr, req: &Message) -> Result<Message, NetError> {
    let mut stream = TcpStream::connect(peer).await?;
    send_message(&mut stream, req).await?;
    loop {
        match recv_message(&mut stream).await? {
            Message::Ping { nonce } => {
                send_message(&mut stream, &Message::Pong { nonce }).await?;
            }
            reply => return Ok(reply),
        }
    }
}

/// Fetches a batch of finalized blocks (with finality evidence) from a peer.
///
/// Used by `catch_up_from_peer_parallel` to fetch multiple blocks in a single round-trip,
/// enabling parallel finality verification of multiple blocks per epoch.
pub async fn fetch_batch(
    peer: SocketAddr,
    from_height: u64,
    limit: u8,
) -> Result<(Vec<oxydome_net::FinalizedBlockRecord>, u64), NetError> {
    match request(peer, &Message::GetFinalizedBlocks { from_height, limit }).await? {
        Message::FinalizedBlocksResponse {
            blocks,
            tip_height,
            error: None,
        } if blocks.len() <= limit as usize => Ok((blocks, tip_height)),
        Message::FinalizedBlocksResponse {
            error: Some(error), ..
        } => Err(NetError::Unexpected(error)),
        other => Err(NetError::Unexpected(format!("{other:?}"))),
    }
}

/// Fetches the current balances for `owner`.
pub async fn get_balance(peer: SocketAddr, owner: PublicKey) -> Result<BalanceInfo, NetError> {
    match request(peer, &Message::GetBalance { owner }).await? {
        Message::BalanceResponse { info } => Ok(info),
        other => Err(NetError::Unexpected(format!("{other:?}"))),
    }
}

/// Fetches every live UTXO owned by `owner`.
pub async fn get_utxos(peer: SocketAddr, owner: PublicKey) -> Result<Vec<UtxoInfo>, NetError> {
    match request(peer, &Message::GetUtxos { owner }).await? {
        Message::UtxosResponse { entries } => Ok(entries),
        other => Err(NetError::Unexpected(format!("{other:?}"))),
    }
}

/// Fetches an inclusion entry and proof for `outpoint`, if it is still unspent.
pub async fn get_utxo_proof(
    peer: SocketAddr,
    outpoint: OutPoint,
) -> Result<(Option<UtxoEntry>, Option<SparseProof>), NetError> {
    match request(peer, &Message::GetUtxoProof { outpoint }).await? {
        Message::UtxoProofResponse { entry, proof } => Ok((entry, proof)),
        other => Err(NetError::Unexpected(format!("{other:?}"))),
    }
}

/// Fetches the block at `height`, if known.
pub async fn get_block_by_height(peer: SocketAddr, height: u64) -> Result<Option<Block>, NetError> {
    match request(peer, &Message::GetBlockByHeight { height }).await? {
        Message::BlockByHeightResponse { block } => Ok(block.map(|b| *b)),
        other => Err(NetError::Unexpected(format!("{other:?}"))),
    }
}

/// Fetches a transaction and its lifecycle status.
pub async fn get_transaction(
    peer: SocketAddr,
    txid: Hash,
) -> Result<(Option<Transaction>, Option<TxLocation>, TxStatus), NetError> {
    match request(peer, &Message::GetTransaction { txid }).await? {
        Message::TransactionResponse {
            tx,
            location,
            status,
        } => Ok((tx.map(|t| *t), location, status)),
        other => Err(NetError::Unexpected(format!("{other:?}"))),
    }
}

/// Fetches wallet history for `owner`, most recent first, starting at `cursor`.
pub async fn get_history(
    peer: SocketAddr,
    owner: PublicKey,
    cursor: u64,
    limit: u32,
) -> Result<(Vec<HistoryEntry>, u64), NetError> {
    match request(
        peer,
        &Message::GetHistory {
            owner,
            cursor,
            limit,
        },
    )
    .await?
    {
        Message::HistoryResponse {
            entries,
            next_cursor,
        } => Ok((entries, next_cursor)),
        other => Err(NetError::Unexpected(format!("{other:?}"))),
    }
}

/// Fetches a snapshot of the value index.
pub async fn get_value_index(peer: SocketAddr) -> Result<ValueIndexInfo, NetError> {
    match request(peer, &Message::GetValueIndex).await? {
        Message::ValueIndexResponse { info } => Ok(info),
        other => Err(NetError::Unexpected(format!("{other:?}"))),
    }
}

/// Fetches the Ox-committed OHM anchor state for `ohm_id`.
pub async fn get_ohm(peer: SocketAddr, ohm_id: Hash) -> Result<Option<OhmState>, NetError> {
    match request(peer, &Message::GetOhm { ohm_id }).await? {
        Message::OhmResponse { state, .. } => Ok(state.map(|s| *s)),
        other => Err(NetError::Unexpected(format!("{other:?}"))),
    }
}

/// Fetches a private OHM block body by hash.
pub async fn get_ohm_block(peer: SocketAddr, hash: Hash) -> Result<Option<OhmBlock>, NetError> {
    match request(peer, &Message::GetOhmBlock { hash }).await? {
        Message::OhmBlockResponse { block } => Ok(block.map(|b| *b)),
        other => Err(NetError::Unexpected(format!("{other:?}"))),
    }
}

/// Fetches the OHM-local balance of `owner` within `ohm_id`.
pub async fn get_ohm_balance(
    peer: SocketAddr,
    ohm_id: Hash,
    owner: PublicKey,
) -> Result<Amount, NetError> {
    match request(peer, &Message::GetOhmBalance { ohm_id, owner }).await? {
        Message::OhmBalanceResponse { amount, .. } => Ok(amount),
        other => Err(NetError::Unexpected(format!("{other:?}"))),
    }
}

/// Submits a private OHM block, returning its hash, acceptance and rejection reason.
pub async fn submit_ohm_block(
    peer: SocketAddr,
    block: OhmBlock,
) -> Result<(Hash, bool, Option<String>), NetError> {
    match request(
        peer,
        &Message::SubmitOhmBlock {
            block: Box::new(block),
        },
    )
    .await?
    {
        Message::OhmBlockSubmitResponse {
            hash,
            accepted,
            error,
        } => Ok((hash, accepted, error)),
        other => Err(NetError::Unexpected(format!("{other:?}"))),
    }
}

/// Fetches an OHM-hosted OVM contract's code and storage.
pub async fn get_ohm_contract(
    peer: SocketAddr,
    ohm_id: Hash,
    contract_id: Hash,
) -> Result<(Option<Vec<u8>>, Option<Vec<(u64, u64)>>), NetError> {
    match request(
        peer,
        &Message::GetOhmContract {
            ohm_id,
            contract_id,
        },
    )
    .await?
    {
        Message::OhmContractResponse { code, storage, .. } => Ok((code, storage)),
        other => Err(NetError::Unexpected(format!("{other:?}"))),
    }
}

/// Simulates an OHM-hosted contract call, returning the outcome (never mutates state).
pub async fn call_ohm_contract(
    peer: SocketAddr,
    ohm_id: Hash,
    contract_id: Hash,
    entry_point: String,
    arguments: Vec<u64>,
    caller: PublicKey,
    gas_limit: u64,
) -> Result<Message, NetError> {
    request(
        peer,
        &Message::CallOhmContract {
            ohm_id,
            contract_id,
            entry_point,
            arguments,
            caller,
            gas_limit,
        },
    )
    .await
}

/// Fetches the committed cross-OHM outbox of `ohm_id`.
pub async fn get_ohm_outbox(
    peer: SocketAddr,
    ohm_id: Hash,
) -> Result<Vec<OutboundMessage>, NetError> {
    match request(peer, &Message::GetOhmOutbox { ohm_id }).await? {
        Message::OhmOutboxResponse { messages, .. } => Ok(messages),
        other => Err(NetError::Unexpected(format!("{other:?}"))),
    }
}

/// Fetches the committed cross-OHM inbox (consumed receipts) of `ohm_id`.
pub async fn get_ohm_inbox(
    peer: SocketAddr,
    ohm_id: Hash,
) -> Result<Vec<InboundReceipt>, NetError> {
    match request(peer, &Message::GetOhmInbox { ohm_id }).await? {
        Message::OhmInboxResponse { receipts, .. } => Ok(receipts),
        other => Err(NetError::Unexpected(format!("{other:?}"))),
    }
}

/// Submits `tx`, returning its txid, whether it was accepted, and the rejection reason.
pub async fn submit_transaction(
    peer: SocketAddr,
    tx: Transaction,
) -> Result<(Hash, bool, Option<String>), NetError> {
    match request(peer, &Message::SubmitTransaction { tx: Box::new(tx) }).await? {
        Message::SubmitResponse {
            txid,
            accepted,
            error,
        } => Ok((txid, accepted, error)),
        other => Err(NetError::Unexpected(format!("{other:?}"))),
    }
}

/// A live subscription to a node's wallet event stream, driven on a dedicated connection.
pub struct NodeEvents {
    stream: tokio::net::TcpStream,
}

/// Opens a subscription connection for `kinds` (empty means all kinds) and returns the event
/// stream. The connection stays open (and this future pending) until dropped.
pub async fn subscribe(
    peer: SocketAddr,
    kinds: Vec<WalletSubscription>,
) -> Result<NodeEvents, NetError> {
    let mut stream = TcpStream::connect(peer).await?;
    send_message(&mut stream, &Message::Subscribe { kinds }).await?;
    loop {
        match recv_message(&mut stream).await? {
            Message::SubscribeResponse { ok: true, .. } => return Ok(NodeEvents { stream }),
            Message::SubscribeResponse { ok: false, error } => {
                return Err(NetError::Unexpected(format!(
                    "subscribe refused: {error:?}"
                )));
            }
            Message::Ping { nonce } => {
                send_message(&mut stream, &Message::Pong { nonce }).await?;
            }
            other => return Err(NetError::Unexpected(format!("{other:?}"))),
        }
    }
}

impl NodeEvents {
    /// The next event on the subscription stream.
    pub async fn next(&mut self) -> Result<NodeEvent, NetError> {
        loop {
            match recv_message(&mut self.stream).await? {
                Message::Event { event } => return Ok(event),
                Message::Ping { nonce } => {
                    send_message(&mut self.stream, &Message::Pong { nonce }).await?;
                }
                other => return Err(NetError::Unexpected(format!("{other:?}"))),
            }
        }
    }
}

/// Streams filtered events over a subscribed connection until the peer disconnects.
async fn stream_events(
    stream: &mut TcpStream,
    mut rx: broadcast::Receiver<NodeEvent>,
    kinds: Vec<WalletSubscription>,
) {
    loop {
        tokio::select! {
            incoming = recv_message(stream) => {
                match incoming {
                    Ok(Message::Ping { nonce }) => {
                        send_message(stream, &Message::Pong { nonce }).await.ok();
                    }
                    Ok(Message::Unsubscribe) | Err(_) => return,
                    Ok(_) => {}
                }
            }
            event = rx.recv() => {
                match event {
                    Ok(event) => {
                        if kinds_matches(&kinds, &event) {
                            send_message(stream, &Message::Event { event }).await.ok();
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => return,
                }
            }
        }
    }
}

/// Returns true when `event` matches at least one requested subscription kind.
fn kinds_matches(kinds: &[WalletSubscription], event: &NodeEvent) -> bool {
    if kinds.is_empty() {
        return true;
    }
    match event {
        NodeEvent::BlockCommitted { .. } => kinds.contains(&WalletSubscription::NewBlocks),
        NodeEvent::TxAccepted { .. } => kinds.contains(&WalletSubscription::TxAccepted),
        NodeEvent::TxConfirmed { .. } => kinds.contains(&WalletSubscription::TxConfirmed),
        NodeEvent::TxRejected { .. } => kinds.contains(&WalletSubscription::TxRejected),
        NodeEvent::MempoolChanged { .. } => kinds.contains(&WalletSubscription::Mempool),
    }
}
