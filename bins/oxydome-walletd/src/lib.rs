//! Oxydome walletd daemon: an Ethereum-class JSON-RPC and WebSocket API backed by an
//! `oxydome-node` peer. See PLAN.md §12.

pub mod node_client;
pub mod rpc;
pub mod vault;
pub mod ws;
pub mod ws_handler;

use crate::ws_handler::handle_ws;
use oxydome_wallet_rpc::{RpcRequest, RpcResponse};
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use ws::EventHub;

/// Default BIP44 coin type for Oxydome (hardened).
pub const DEFAULT_COIN_TYPE: u32 = 420;

/// Shared application state for the walletd server.
pub struct AppState {
    /// TCP address of the backing Oxydome node.
    pub node_addr: SocketAddr,
    /// Chain ID (hex string).
    pub chain_id: String,
    /// Genesis block hash (hex string).
    pub genesis_hash: String,
    /// The HD wallet vault.
    pub vault: Mutex<vault::VaultHandle>,
    /// Event distribution hub for WebSocket subscriptions.
    pub hub: EventHub,
}

impl AppState {
    /// Returns the next subscription ID.
    pub fn next_sub_id(&self) -> u64 {
        self.hub.next_sub_id()
    }
}

/// Runs the walletd HTTP+WebSocket server on `addr`, connected to a node at `node_addr`.
pub async fn serve(
    addr: SocketAddr,
    node_addr: SocketAddr,
    chain_id: String,
    genesis_hash: String,
) -> anyhow::Result<()> {
    let state = Arc::new(AppState {
        node_addr,
        chain_id,
        genesis_hash,
        vault: Mutex::new(vault::VaultHandle::new()),
        hub: EventHub::new(),
    });

    // Spawn the node event listener that feeds the hub.
    let hub_tx = state.hub.sender().clone();
    let node_addr_clone = node_addr;
    tokio::spawn(async move {
        node_event_listener(node_addr_clone, hub_tx).await;
    });

    let app = axum::Router::new()
        .route("/", axum::routing::post(handle_rpc))
        .route("/health", axum::routing::get(handle_health))
        .route(
            "/ws",
            axum::routing::get({
                let state = Arc::clone(&state);
                move |ws: axum::extract::ws::WebSocketUpgrade| {
                    let state = Arc::clone(&state);
                    async move { ws.on_upgrade(move |socket| handle_ws(socket, state)) }
                }
            }),
        )
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// Listens to node events and forwards them to the hub as WebSocket notices.
async fn node_event_listener(
    node_addr: SocketAddr,
    hub: tokio::sync::broadcast::Sender<crate::ws::WsNotice>,
) {
    use oxydome_net::WalletSubscription;
    use oxydome_node::server::subscribe as node_subscribe;

    let kinds = vec![
        WalletSubscription::NewBlocks,
        WalletSubscription::TxAccepted,
        WalletSubscription::TxConfirmed,
        WalletSubscription::TxRejected,
        WalletSubscription::Mempool,
    ];

    loop {
        match node_subscribe(node_addr, kinds.clone()).await {
            Ok(mut events) => {
                while let Ok(event) = events.next().await {
                    let notice = node_event_to_notice(&event);
                    let _ = hub.send(notice);
                }
            }
            Err(_) => {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
    }
}

/// Converts a node event into a WebSocket notice.
fn node_event_to_notice(event: &oxydome_net::NodeEvent) -> crate::ws::WsNotice {
    use oxydome_net::NodeEvent;
    let (topic, result) = match event {
        NodeEvent::BlockCommitted {
            height,
            block_hash,
            txids,
        } => (
            "newBlocks",
            serde_json::json!({
                "blockHash": oxydome_wallet_rpc::to_hex(block_hash.as_bytes()),
                "height": height,
                "txids": txids.iter().map(|t| oxydome_wallet_rpc::to_hex(t.as_bytes())).collect::<Vec<_>>(),
            }),
        ),
        NodeEvent::TxAccepted { txid, .. } => (
            "txAccepted",
            serde_json::json!({ "txid": oxydome_wallet_rpc::to_hex(txid.as_bytes()) }),
        ),
        NodeEvent::TxConfirmed { txid, location, .. } => (
            "txConfirmed",
            serde_json::json!({
                "txid": oxydome_wallet_rpc::to_hex(txid.as_bytes()),
                "height": location.height,
                "blockHash": oxydome_wallet_rpc::to_hex(location.block_hash.as_bytes()),
            }),
        ),
        NodeEvent::TxRejected { txid, reason, .. } => (
            "txFailed",
            serde_json::json!({
                "txid": oxydome_wallet_rpc::to_hex(txid.as_bytes()),
                "reason": reason,
            }),
        ),
        NodeEvent::MempoolChanged { txid, added, .. } => (
            "mempool",
            serde_json::json!({
                "txid": oxydome_wallet_rpc::to_hex(txid.as_bytes()),
                "added": added,
            }),
        ),
    };
    crate::ws::WsNotice {
        jsonrpc: "2.0".into(),
        method: "ox_subscription".into(),
        params: crate::ws::WsParams {
            subscription: topic.to_string(),
            result,
        },
    }
}

/// POST / — JSON-RPC 2.0 endpoint.
async fn handle_rpc(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    body: String,
) -> axum::Json<RpcResponse> {
    let req: RpcRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => {
            return axum::Json(RpcResponse::error(
                Value::Null,
                oxydome_wallet_rpc::RpcError::new(
                    oxydome_wallet_rpc::RpcError::INVALID_REQUEST,
                    "invalid JSON-RPC request",
                ),
            ));
        }
    };
    let resp = rpc::dispatch(&state, &req).await;
    axum::Json(resp)
}

/// GET /health — liveness probe.
async fn handle_health() -> &'static str {
    "ok"
}
