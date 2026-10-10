//! Bounded local storage for optional, content-addressed application assets.
//!
//! This store is deliberately outside `ChainState`: asset availability and retrieval never
//! affect transaction validity, OVM execution, or consensus state roots.

use oxydome_crypto::Hash;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const MAX_CONTENT_ITEMS: usize = 4096;
const MAX_CONTENT_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ContentStoreError {
    #[error("content storage I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("content hash does not match supplied bytes")]
    HashMismatch,
    #[error("content exceeds the per-item size limit")]
    ItemTooLarge,
    #[error("content store capacity exceeded")]
    CapacityExceeded,
    #[error("invalid or corrupted content store entry {0}")]
    Corrupt(String),
}

#[derive(Debug, Default)]
pub struct ContentStore {
    root: Option<PathBuf>,
    entries: BTreeMap<Hash, Vec<u8>>,
    total_bytes: u64,
}

impl ContentStore {
    pub fn open(path: &Path) -> Result<Self, ContentStoreError> {
        std::fs::create_dir_all(path)?;
        let mut store = Self {
            root: Some(path.to_path_buf()),
            ..Self::default()
        };
        for item in std::fs::read_dir(path)? {
            let item = item?;
            let file_type = item.file_type()?;
            if !file_type.is_file() {
                continue;
            }
            let name = item.file_name();
            let name = name
                .to_str()
                .ok_or_else(|| ContentStoreError::Corrupt(item.path().display().to_string()))?;
            if name.ends_with(".tmp") {
                continue;
            }
            let key_bytes =
                hex::decode(name).map_err(|_| ContentStoreError::Corrupt(name.to_owned()))?;
            let hash = Hash::from_slice(&key_bytes)
                .ok_or_else(|| ContentStoreError::Corrupt(name.to_owned()))?;
            let bytes = std::fs::read(item.path())?;
            store.insert_loaded(hash, bytes)?;
        }
        Ok(store)
    }

    pub fn get(&self, hash: &Hash) -> Option<&[u8]> {
        self.entries.get(hash).map(Vec::as_slice)
    }

    pub fn put(&mut self, expected_hash: Hash, bytes: Vec<u8>) -> Result<(), ContentStoreError> {
        if bytes.len() as u64 > oxydome_ovm::MAX_ASSET_BYTES {
            return Err(ContentStoreError::ItemTooLarge);
        }
        if oxydome_ovm::content_hash(&bytes) != expected_hash {
            return Err(ContentStoreError::HashMismatch);
        }
        if self.entries.contains_key(&expected_hash) {
            return Ok(());
        }
        if self.entries.len() >= MAX_CONTENT_ITEMS
            || self.total_bytes.saturating_add(bytes.len() as u64) > MAX_CONTENT_BYTES
        {
            return Err(ContentStoreError::CapacityExceeded);
        }

        if let Some(root) = &self.root {
            let destination = root.join(expected_hash.to_hex());
            let temporary = root.join(format!("{}.tmp", expected_hash.to_hex()));
            use std::io::Write;
            let mut file = std::fs::File::create(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            std::fs::rename(temporary, destination)?;
        }
        self.total_bytes = self.total_bytes.saturating_add(bytes.len() as u64);
        self.entries.insert(expected_hash, bytes);
        Ok(())
    }

    fn insert_loaded(&mut self, hash: Hash, bytes: Vec<u8>) -> Result<(), ContentStoreError> {
        if bytes.len() as u64 > oxydome_ovm::MAX_ASSET_BYTES
            || oxydome_ovm::content_hash(&bytes) != hash
            || self.entries.contains_key(&hash)
        {
            return Err(ContentStoreError::Corrupt(hash.to_hex()));
        }
        if self.entries.len() >= MAX_CONTENT_ITEMS
            || self.total_bytes.saturating_add(bytes.len() as u64) > MAX_CONTENT_BYTES
        {
            return Err(ContentStoreError::CapacityExceeded);
        }
        self.total_bytes = self.total_bytes.saturating_add(bytes.len() as u64);
        self.entries.insert(hash, bytes);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_only_content_matching_its_hash() {
        let mut store = ContentStore::default();
        let bytes = b"optional app asset".to_vec();
        let hash = oxydome_ovm::content_hash(&bytes);
        store.put(hash, bytes.clone()).unwrap();
        assert_eq!(store.get(&hash), Some(bytes.as_slice()));
        assert!(matches!(
            store.put(hash, b"tampered".to_vec()),
            Err(ContentStoreError::HashMismatch)
        ));
    }

    #[test]
    fn persists_content_under_its_hash_and_reloads_it() {
        let directory = tempfile::tempdir().unwrap();
        let bytes = b"<html>Oxydome</html>".to_vec();
        let hash = oxydome_ovm::content_hash(&bytes);
        ContentStore::open(directory.path())
            .unwrap()
            .put(hash, bytes.clone())
            .unwrap();
        let reopened = ContentStore::open(directory.path()).unwrap();
        assert_eq!(reopened.get(&hash), Some(bytes.as_slice()));
    }
}
