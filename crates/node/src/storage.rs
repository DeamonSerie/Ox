//! Peer node storage labeler.

use oxydome_core::{evfs_label_commitment_v2, label_commitment, StorageLabel};
use oxydome_crypto::evk::FileEvkLabel;
use oxydome_crypto::{hash_value, merkle_root, Hash, KeyPair, PublicKey};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub struct LabelerConfig {
    pub node_keypair: KeyPair,
    pub node_public: PublicKey,
    pub capacity_bytes: u64,
    pub data_dir: PathBuf,
    pub content_store_root: PathBuf,
    pub index_store_path: PathBuf,
}

#[derive(Debug, Clone, Default)]
pub struct LabelerState {
    pub last_height: u64,
    pub last_timestamp: u64,
    pub last_label: Option<StorageLabel>,
    pub last_file_root: Option<Hash>,
    pub file_count: u64,
    pub file_storage_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct Labeler {
    config: LabelerConfig,
    state: Arc<Mutex<LabelerState>>,
}

impl Labeler {
    pub fn new(config: LabelerConfig) -> Self {
        Self {
            config,
            state: Arc::new(Mutex::new(LabelerState::default())),
        }
    }

    fn used_bytes(&self) -> u64 {
        let mut total = 0u64;
        total = total.saturating_add(dir_size(&self.config.data_dir));
        total = total.saturating_add(dir_size(&self.config.content_store_root));
        total = total.saturating_add(file_size(&self.config.index_store_path));
        total
    }

    pub fn capacity(&self) -> u64 {
        self.config.capacity_bytes
    }

    /// Computes a Merkle root over the node's file labels for inclusion in the storage label.
    pub fn compute_file_root(&self, labels: &[FileEvkLabel]) -> Hash {
        let leaves: Vec<Hash> = labels.iter().map(|l| hash_value(l)).collect();
        merkle_root(&leaves)
    }

    pub fn generate_label(&self, height: u64, timestamp: u64) -> StorageLabel {
        self.generate_label_internal(height, timestamp, None, 0, 0)
    }

    /// Generates a v2 storage label that includes file-system metadata when file state is present.
    pub fn generate_label_with_files(
        &self,
        height: u64,
        timestamp: u64,
        file_labels: &[FileEvkLabel],
        file_count: u64,
        file_storage_bytes: u64,
    ) -> StorageLabel {
        let file_root = if file_labels.is_empty() {
            None
        } else {
            Some(self.compute_file_root(file_labels))
        };
        self.generate_label_internal(height, timestamp, file_root, file_count, file_storage_bytes)
    }

    fn generate_label_internal(
        &self,
        height: u64,
        timestamp: u64,
        file_root: Option<Hash>,
        file_count: u64,
        file_storage_bytes: u64,
    ) -> StorageLabel {
        let used = self.used_bytes();
        let capacity = self.config.capacity_bytes;
        let available = capacity.saturating_sub(used);
        let commitment = if file_root.is_some() || file_count > 0 || file_storage_bytes > 0 {
            evfs_label_commitment_v2(&StorageLabel {
                node: self.config.node_public,
                height,
                capacity_bytes: capacity,
                used_bytes: used,
                available_bytes: available,
                timestamp,
                signature: oxydome_crypto::Sig([0u8; 64]),
                file_root,
                file_count,
                file_storage_bytes,
            })
        } else {
            label_commitment(
                self.config.node_public,
                height,
                capacity,
                used,
                available,
                timestamp,
            )
        };
        let signature = self.config.node_keypair.sign(&commitment.0);
        StorageLabel {
            node: self.config.node_public,
            height,
            capacity_bytes: capacity,
            used_bytes: used,
            available_bytes: available,
            timestamp,
            signature,
            file_root,
            file_count,
            file_storage_bytes,
        }
    }

    pub fn update_last_label(&self, height: u64, timestamp: u64, label: &StorageLabel) {
        let mut state = self.state.lock().expect("labeler mutex poisoned");
        state.last_height = height;
        state.last_timestamp = timestamp;
        state.last_label = Some(label.clone());
    }

    pub fn last_label(&self) -> Option<StorageLabel> {
        let state = self.state.lock().expect("labeler mutex poisoned");
        state.last_label.clone()
    }

    /// Updates the labeler's file metadata.
    pub fn update_file_metadata(
        &self,
        file_root: Option<Hash>,
        file_count: u64,
        file_storage_bytes: u64,
    ) {
        let mut state = self.state.lock().expect("labeler mutex poisoned");
        state.last_file_root = file_root;
        state.file_count = file_count;
        state.file_storage_bytes = file_storage_bytes;
    }

    /// Returns the labeler's current file system metadata.
    pub fn file_metadata(&self) -> (Option<Hash>, u64, u64) {
        let state = self.state.lock().expect("labeler mutex poisoned");
        (
            state.last_file_root,
            state.file_count,
            state.file_storage_bytes,
        )
    }
}

fn dir_size(path: &PathBuf) -> u64 {
    let mut total = 0u64;
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                total = total.saturating_add(dir_size(&p));
            } else if p.is_file() {
                total = total.saturating_add(file_size(&p));
            }
        }
    }
    total
}

fn file_size(path: &PathBuf) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}
