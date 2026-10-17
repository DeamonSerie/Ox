//! Async TCP server for a master node.
//!
//! Masters accept admission requests and liveness pings. They never store or serve block
//! bodies, so the server deliberately handles only the messages a master is responsible for.
//!
//! Block auditing is performed via `smol::unblock` (see `crate::async_audit`) so that
//! the tokio TCP accept loop is never blocked by header-only verification.

use crate::{async_audit, MasterNode};
use oxydome_net::{recv_message, send_message, Message};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::{TcpListener, TcpStream};

/// Runs the master accept loop until the process exits.
pub async fn run(addr: &str, node: MasterNode) -> std::io::Result<SocketAddr> {
    let listener = TcpListener::bind(addr).await?;
    let _local = listener.local_addr()?;
    let shared = Arc::new(Mutex::new(node));
    loop {
        let (stream, _peer) = listener.accept().await?;
        let shared = Arc::clone(&shared);
        tokio::spawn(async move {
            let _ = handle_connection(stream, shared).await;
        });
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    node: Arc<Mutex<MasterNode>>,
) -> std::io::Result<()> {
    loop {
        let msg = match recv_message(&mut stream).await {
            Ok(m) => m,
            Err(_) => return Ok(()),
        };
        // Compute any reply synchronously so no mutex guard is held across an await point.
        let reply: Option<Message> = match msg {
            Message::Ping { nonce } => Some(Message::Pong { nonce }),
            Message::AdmitRequest {
                node: requester,
                manifest_root,
                manifest,
                timestamp,
                chain_id: req_chain_id,
                ..
            } => {
                let (local_chain_id, mismatch) = {
                    let guard = node.lock().unwrap();
                    let local_id = crate::mvms::compute_chain_id(
                        &guard.params.chain_name,
                        &guard.params.currency_symbol,
                    );
                    let mismatch = req_chain_id
                        .as_ref()
                        .map(|id| id != &local_id)
                        .unwrap_or(false);
                    (local_id, mismatch)
                };

                if mismatch {
                    Some(Message::AdmitResponse {
                        certificate: None,
                        reason: Some("chain_id does not match master chain".into()),
                        chain_id: Some(local_chain_id),
                    })
                } else {
                    let computed = manifest.root();
                    if computed != manifest_root {
                        Some(Message::AdmitResponse {
                            certificate: None,
                            reason: Some("manifest root does not match submitted manifest".into()),
                            chain_id: Some(local_chain_id),
                        })
                    } else {
                        let result = {
                            let mut guard = node.lock().unwrap();
                            guard.handle_admission(requester, manifest_root, timestamp)
                        };
                        Some(match result {
                            Ok(cert) => Message::AdmitResponse {
                                certificate: Some(Box::new(cert)),
                                reason: None,
                                chain_id: Some(local_chain_id),
                            },
                            Err(reason) => Message::AdmitResponse {
                                certificate: None,
                                reason: Some(reason),
                                chain_id: Some(local_chain_id),
                            },
                        })
                    }
                }
            }
            // Masters serve header metadata only, never block bodies.
            Message::GetHeaders { .. } => Some(Message::HeadersResponse { blocks: Vec::new() }),
            Message::GetFinalizedBlocks { .. } => {
                let tip_height = node.lock().unwrap().chain.head().height;
                Some(Message::FinalizedBlocksResponse {
                    blocks: Vec::new(),
                    tip_height,
                    error: Some("masters do not serve block history".into()),
                })
            }
            // A leader asks the masters to audit a proposed block.
            // Uses smol::unblock so the tokio accept loop is not blocked by verification.
            Message::Proposal { package, .. } => {
                let master_clone = { node.lock().unwrap().clone() };
                match async_audit::audit_async(&master_clone, &package).await {
                    Ok(attestation) => Some(Message::Attestation { attestation }),
                    Err(e) => {
                        eprintln!("audit failed: {e}");
                        None
                    }
                }
            }
            // A finalized block extends the master's header chain.
            Message::FinalizedBlock { finalized } => {
                if let Err(error) = node.lock().unwrap().on_finalized(&finalized) {
                    eprintln!("rejected finalized block header: {error}");
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
