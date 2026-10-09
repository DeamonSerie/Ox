//! WebSocket handler for walletd subscriptions.
//!
//! Manages the `/ws` endpoint: clients connect, send `ox_subscribe`/`ox_unsubscribe`
//! JSON-RPC methods, and receive filtered event notifications.

use crate::AppState;
use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::broadcast;

/// Handles a WebSocket connection, managing subscriptions and event forwarding.
pub async fn handle_ws(socket: WebSocket, state: Arc<AppState>) {
    let hub = state.hub.sender().clone();
    let (mut sender, mut receiver) = socket.split();
    let mut rx = hub.subscribe();
    let mut subscriptions: HashSet<String> = HashSet::new();

    loop {
        tokio::select! {
            // Incoming message from the client
            msg = receiver.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        let req: Value = match serde_json::from_str(&text) {
                            Ok(v) => v,
                            Err(_) => continue,
                        };
                        let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
                        let id = req.get("id").cloned().unwrap_or(Value::Null);

                        match method {
                            "ox_subscribe" => {
                                let _topics = req
                                    .get("params")
                                    .and_then(|p| p.as_array())
                                    .map(|arr| {
                                        arr.iter()
                                            .filter_map(|t| t.as_str().map(|s| s.to_string()))
                                            .collect::<Vec<_>>()
                                    })
                                    .unwrap_or_default();
                                let sub_id = format!("0x{:x}", subscriptions.len() + 1);
                                subscriptions.insert(sub_id.clone());
                                let resp = serde_json::json!({
                                    "jsonrpc": "2.0",
                                    "id": id,
                                    "result": sub_id,
                                });
                                let _ = sender.send(Message::Text(resp.to_string())).await;
                            }
                            "ox_unsubscribe" => {
                                let sub_id = req
                                    .get("params")
                                    .and_then(|p| p.as_array())
                                    .and_then(|a| a.first())
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("");
                                subscriptions.remove(sub_id);
                                let resp = serde_json::json!({
                                    "jsonrpc": "2.0",
                                    "id": id,
                                    "result": true,
                                });
                                let _ = sender.send(Message::Text(resp.to_string())).await;
                            }
                            _ => {}
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(_)) => break,
                    _ => {}
                }
            }
            // Event from the hub
            event = rx.recv() => {
                match event {
                    Ok(notice) => {
                        let text = serde_json::to_string(&notice).unwrap();
                        if sender.send(Message::Text(text)).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
}
