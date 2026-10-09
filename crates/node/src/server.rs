//! Async TCP server and client helpers for a server node.
//!
//! The server handles liveness, chain synchronisation and admission responses. Consensus
//! rounds are driven by [`crate::sim`], which exchanges the same [`oxydome_net::Message`]
//! values between nodes; this keeps the wire format identical whether the messages travel
//! over a socket or through the in-process simulation.

use crate::Node;
use oxydome_consensus::AdmissionCertificate;
use oxydome_core::{Block, Hash, OutPoint, PublicKey, Transaction};
use oxydome_crypto::SparseProof;
use oxydome_net::{
    recv_message, send_message, BalanceInfo, HistoryEntry, Message, NetError, NodeEvent,
    TxLocation, TxStatus, UtxoInfo, ValueIndexInfo, WalletSubscription,
};
use oxydome_state::UtxoEntry;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;

/// Shared node handle for the async server.
pub type SharedNode = Arc<Mutex<Node>>;

/// Runs the node accept loop until the process exits.
pub async fn run(addr: &str, node: Node) -> std::io::Result<SocketAddr> {
    let listener = TcpListener::bind(addr).await?;
    let _local = listener.local_addr()?;
    let shared: SharedNode = Arc::new(Mutex::new(node));
    loop {
        let (stream, _peer) = listener.accept().await?;
        let shared = Arc::clone(&shared);
        tokio::spawn(async move {
            let _ = handle_connection(stream, shared).await;
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
    let listener = TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    let shared: SharedNode = Arc::new(Mutex::new(node));
    let accept_shared = Arc::clone(&shared);
    tokio::spawn(async move {
        loop {
            let (stream, _peer) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(_) => return,
            };
            let shared = Arc::clone(&accept_shared);
            tokio::spawn(async move {
                let _ = handle_connection(stream, shared).await;
            });
        }
    });
    Ok((local, shared))
}

async fn handle_connection(mut stream: TcpStream, node: SharedNode) -> std::io::Result<()> {
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
            _ => None,
        };
        if let Some(reply) = reply {
            send_message(&mut stream, &reply).await.ok();
        }
    }
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
        },
    )
    .await
    .ok();
    loop {
        match recv_message(&mut stream).await {
            Ok(Message::AdmitResponse {
                certificate,
                reason,
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

/// Fetches all blocks from a peer starting at `from_height`.
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
