//! On-disk application configuration.
//!
//! A single TOML file describes the genesis distribution, the founding master/node sets with
//! their network addresses and key seeds, the approved software manifests, and the chain
//! parameters. Both the node and master binaries load the same file.

use crate::{Amount, ChainParams, GenesisAllocation, GenesisConfig, PublicKey};
use oxydome_crypto::KeyPair;
use serde::{Deserialize, Serialize};

/// One master or server node: identity, signing seed and listen address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointConfig {
    /// Human-readable label used to select this endpoint on the command line.
    pub name: String,
    /// Ed25519 public key (hex, 32 bytes).
    pub key: String,
    /// Ed25519 secret seed (hex, 32 bytes). Present for endpoints this host runs.
    #[serde(default)]
    pub seed: Option<String>,
    /// Listen address, e.g. `127.0.0.1:7000`.
    #[serde(default)]
    pub addr: String,
}

/// A genesis account allocation, by hex public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllocationConfig {
    pub recipient: String,
    pub amount: Amount,
}

/// The full network configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub params: ChainParams,
    #[serde(default)]
    pub timestamp: u64,
    pub allocations: Vec<AllocationConfig>,
    pub masters: Vec<EndpointConfig>,
    pub nodes: Vec<EndpointConfig>,
    /// Approved `CodeManifest` roots (hex).
    #[serde(default)]
    pub approved_manifests: Vec<String>,
    #[serde(default)]
    pub node_capacity_bytes: Option<u64>,
}

/// Configuration errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("invalid hex key: {0}")]
    BadKey(String),
    #[error("invalid hex seed for {0}")]
    BadSeed(String),
    #[error("endpoint {0} is missing a key seed")]
    MissingSeed(String),
    #[error("unknown endpoint {0}")]
    UnknownEndpoint(String),
    #[error("allocation total {0} does not equal genesis supply {1}")]
    SupplyMismatch(Amount, Amount),
    #[error("configuration has no masters")]
    NoMasters,
}

fn parse_public(hex_key: &str) -> Result<PublicKey, ConfigError> {
    let bytes = hex::decode(hex_key).map_err(|_| ConfigError::BadKey(hex_key.to_string()))?;
    PublicKey::from_slice(&bytes).ok_or_else(|| ConfigError::BadKey(hex_key.to_string()))
}

fn parse_seed(hex_seed: &str, name: &str) -> Result<KeyPair, ConfigError> {
    let bytes = hex::decode(hex_seed).map_err(|_| ConfigError::BadSeed(name.to_string()))?;
    KeyPair::from_seed_slice(&bytes).ok_or_else(|| ConfigError::BadSeed(name.to_string()))
}

impl EndpointConfig {
    pub fn public(&self) -> Result<PublicKey, ConfigError> {
        parse_public(&self.key)
    }

    pub fn keypair(&self) -> Result<KeyPair, ConfigError> {
        let seed = self
            .seed
            .as_deref()
            .ok_or_else(|| ConfigError::MissingSeed(self.name.clone()))?;
        parse_seed(seed, &self.name)
    }
}

impl AppConfig {
    /// The genesis configuration these settings describe.
    pub fn genesis(&self) -> Result<GenesisConfig, ConfigError> {
        if self.masters.is_empty() {
            return Err(ConfigError::NoMasters);
        }
        let mut allocations = Vec::with_capacity(self.allocations.len());
        for a in &self.allocations {
            allocations.push(GenesisAllocation {
                recipient: parse_public(&a.recipient)?,
                amount: a.amount,
            });
        }
        let config = GenesisConfig {
            params: self.params.clone(),
            allocations,
            masters: self
                .masters
                .iter()
                .map(|m| m.public())
                .collect::<Result<Vec<_>, _>>()?,
            nodes: self
                .nodes
                .iter()
                .map(|n| n.public())
                .collect::<Result<Vec<_>, _>>()?,
            timestamp: self.timestamp,
        };
        if config.allocated_supply() != self.params.genesis_supply {
            return Err(ConfigError::SupplyMismatch(
                config.allocated_supply(),
                self.params.genesis_supply,
            ));
        }
        Ok(config)
    }

    pub fn master(&self, name: &str) -> Result<&EndpointConfig, ConfigError> {
        self.masters
            .iter()
            .find(|m| m.name == name)
            .ok_or_else(|| ConfigError::UnknownEndpoint(name.to_string()))
    }

    pub fn node(&self, name: &str) -> Result<&EndpointConfig, ConfigError> {
        self.nodes
            .iter()
            .find(|n| n.name == name)
            .ok_or_else(|| ConfigError::UnknownEndpoint(name.to_string()))
    }

    pub fn approved_manifest_roots(&self) -> Result<Vec<crate::Hash>, ConfigError> {
        self.approved_manifests
            .iter()
            .map(|s| {
                let bytes = hex::decode(s).map_err(|_| ConfigError::BadKey(s.clone()))?;
                crate::Hash::from_slice(&bytes).ok_or_else(|| ConfigError::BadKey(s.clone()))
            })
            .collect()
    }
}

/// The canonical manifest of the reference node software. The node side builds the same
/// manifest via [`oxydome_node::reference_manifest`], and the `init` command presets its root
/// as approved.
pub fn reference_manifest_tag() -> &'static [u8] {
    b"oxydome-node/0.1.0"
}
