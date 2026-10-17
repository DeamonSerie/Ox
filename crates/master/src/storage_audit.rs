//! Storage auditor for admin/master software.

use oxydome_core::{StorageAuditResult, StorageLabel};
use oxydome_crypto::PublicKey;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::Duration;

use oxydome_net::{recv_message, send_message, Message};
use tokio::net::TcpStream;

pub struct StorageAuditor {
    expected_network_storage: u64,
    max_deviation_bps: u32,
    timeout: Duration,
}

impl StorageAuditor {
    pub fn new(expected_network_storage: u64, max_deviation_bps: u32) -> Self {
        Self {
            expected_network_storage,
            max_deviation_bps,
            timeout: Duration::from_secs(5),
        }
    }

    pub async fn audit(
        &self,
        epoch: u64,
        node_addrs: &BTreeMap<PublicKey, SocketAddr>,
        auditor_measurements: &BTreeMap<PublicKey, u64>,
    ) -> StorageAuditResult {
        let mut per_node = BTreeMap::new();
        let mut network_available: u64 = 0;

        for (node_pub, addr) in node_addrs {
            let mut compliant = false;
            if let Some(auditor_avail) = auditor_measurements.get(node_pub) {
                if let Ok(label) = self.request_label(*addr).await {
                    if label.node == *node_pub && label.is_valid() {
                        network_available = network_available.saturating_add(label.available_bytes);
                        if label.within_deviation(*auditor_avail, self.max_deviation_bps) {
                            compliant = true;
                        }
                    }
                }
            }
            per_node.insert(*node_pub, compliant);
        }

        let expected = self.expected_network_storage;
        let mut overall_compliant = true;
        if expected > 0 && network_available < expected {
            overall_compliant = false;
        }
        if per_node.values().any(|v| !*v) {
            overall_compliant = false;
        }

        StorageAuditResult {
            epoch,
            per_node,
            network_available,
            expected_network_storage: expected,
            compliant: overall_compliant,
        }
    }

    async fn request_label(
        &self,
        addr: SocketAddr,
    ) -> Result<StorageLabel, Box<dyn std::error::Error>> {
        let mut stream = TcpStream::connect(addr).await?;
        let msg = Message::StorageLabelRequest { nonce: 0 };
        send_message(&mut stream, &msg).await?;
        let resp = recv_message(&mut stream).await?;
        match resp {
            Message::StorageLabelResponse { label } => Ok(label),
            _ => Err("unexpected response".into()),
        }
    }
}
