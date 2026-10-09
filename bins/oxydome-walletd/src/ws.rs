//! WebSocket support for the walletd server.
//!
//! Manages the event distribution hub: node events are received on a dedicated subscription
//! connection and broadcast to all connected WebSocket clients, filtered by topic.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

/// A WebSocket notification sent to a subscribed client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsNotice {
    pub jsonrpc: String,
    pub method: String,
    pub params: WsParams,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsParams {
    pub subscription: String,
    pub result: serde_json::Value,
}

/// The event distribution hub. Node events are sent here and fanned out to all subscribers.
#[derive(Clone)]
pub struct EventHub {
    tx: tokio::sync::broadcast::Sender<WsNotice>,
    next_id: std::sync::Arc<AtomicU64>,
}

impl EventHub {
    pub fn new() -> Self {
        let (tx, _) = tokio::sync::broadcast::channel(4096);
        Self {
            tx,
            next_id: std::sync::Arc::new(AtomicU64::new(1)),
        }
    }

    /// Returns the sender for node events.
    pub fn sender(&self) -> &tokio::sync::broadcast::Sender<WsNotice> {
        &self.tx
    }

    /// Subscribes to the event stream.
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<WsNotice> {
        self.tx.subscribe()
    }

    /// Generates the next subscription ID.
    pub fn next_sub_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::SeqCst)
    }
}

impl Default for EventHub {
    fn default() -> Self {
        Self::new()
    }
}
