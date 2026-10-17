//! Master Virtual Machine Starter (MVMS) core logic.
//!
//! Provides the MVMS node and bootstrap environment that allows developers
//! to launch custom Ox-like sovereign blockchains with customizable parameters,
//! renamed currencies, and mechanism compatibility.

use crate::mvms_config::MvmsConfig;
use crate::MasterNode;
use oxydome_core::{Block, ChainParams, PublicKey};
use oxydome_crypto::{hash_value, KeyPair};
use oxydome_state::ChainState;

/// An MVMS-configured Master node runner.
#[derive(Debug)]
pub struct MvmsMaster {
    /// The configuration specifying chain name, currency symbol, and parameters.
    pub config: MvmsConfig,
    /// The underlying MasterNode instance running the chain.
    pub node: MasterNode,
    /// The computed genesis block for this custom chain.
    pub genesis_block: Block,
    /// The unique chain identifier derived from chain name and currency symbol.
    pub chain_id: String,
}

impl MvmsMaster {
    /// Initializes an MVMS Master node with custom configuration.
    pub fn new(
        key: KeyPair,
        config: MvmsConfig,
        other_masters: Vec<PublicKey>,
        nodes: Vec<PublicKey>,
    ) -> Result<Self, String> {
        config.validate()?;

        let mut all_masters = vec![key.public()];
        for m in other_masters {
            if !all_masters.contains(&m) {
                all_masters.push(m);
            }
        }

        let genesis_cfg = config.to_genesis_config(all_masters, nodes);
        let (_, genesis_block, gov) = ChainState::genesis(&genesis_cfg)
            .map_err(|e| format!("Failed to generate MVMS genesis: {}", e))?;

        let chain_id = compute_chain_id(&config.chain_name, &config.currency_symbol);
        let node = MasterNode::new(key, gov, genesis_cfg.params, &genesis_block);

        Ok(Self {
            config,
            node,
            genesis_block,
            chain_id,
        })
    }

    /// Returns the human-readable chain name.
    pub fn chain_name(&self) -> &str {
        &self.config.chain_name
    }

    /// Returns the active currency symbol.
    pub fn currency_symbol(&self) -> &str {
        &self.config.currency_symbol
    }

    /// Returns the chain identifier string.
    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }

    /// Validates that an incoming peer or inter-chain connection matches this chain's ID.
    pub fn validate_peer_chain(&self, peer_chain_id: &str) -> Result<(), String> {
        if self.chain_id == peer_chain_id {
            Ok(())
        } else {
            Err(format!(
                "Chain ID mismatch: local is '{}', peer is '{}'",
                self.chain_id, peer_chain_id
            ))
        }
    }

    /// Validates whether proposed parameters from a peer fall within acceptable limits.
    pub fn negotiate_parameters(&self, proposed: &ChainParams) -> Result<(), String> {
        if proposed.chain_name != self.config.chain_name {
            return Err(format!(
                "chain_name mismatch: expected {}, got {}",
                self.config.chain_name, proposed.chain_name
            ));
        }
        if proposed.currency_symbol != self.config.currency_symbol {
            return Err(format!(
                "currency_symbol mismatch: expected {}, got {}",
                self.config.currency_symbol, proposed.currency_symbol
            ));
        }
        Ok(())
    }
}

/// Derives a deterministic chain ID string from chain name and currency symbol.
pub fn compute_chain_id(chain_name: &str, currency_symbol: &str) -> String {
    let digest = hash_value(&(chain_name, currency_symbol));
    format!(
        "{}-{}-{}",
        chain_name.to_lowercase(),
        currency_symbol.to_lowercase(),
        &digest.to_hex()[..8]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mvms_config::profiles;

    #[test]
    fn test_mvms_master_creation() {
        let key = KeyPair::generate();
        let config = profiles::custom("NovaChain", "NOVA", 5_000_000);
        let mvms = MvmsMaster::new(key, config, vec![], vec![]).expect("create mvms master");

        assert_eq!(mvms.chain_name(), "NovaChain");
        assert_eq!(mvms.currency_symbol(), "NOVA");
        assert!(mvms.chain_id().starts_with("novachain-nova-"));
        assert_eq!(mvms.node.params.genesis_supply, 5_000_000);
        assert_eq!(mvms.node.params.chain_name, "NovaChain");
        assert_eq!(mvms.node.params.currency_symbol, "NOVA");
    }

    #[test]
    fn test_peer_chain_validation() {
        let key = KeyPair::generate();
        let config = profiles::testnet();
        let mvms = MvmsMaster::new(key, config, vec![], vec![]).expect("create testnet mvms");

        let correct_id = mvms.chain_id().to_string();
        assert!(mvms.validate_peer_chain(&correct_id).is_ok());
        assert!(mvms.validate_peer_chain("other-chain-id").is_err());
    }

    #[test]
    fn test_parameter_negotiation() {
        let key = KeyPair::generate();
        let config = profiles::devnet();
        let mvms =
            MvmsMaster::new(key, config.clone(), vec![], vec![]).expect("create devnet mvms");

        let valid_params = config.to_chain_params();
        assert!(mvms.negotiate_parameters(&valid_params).is_ok());

        let mut invalid_params = valid_params.clone();
        invalid_params.chain_name = "WrongChain".to_string();
        assert!(mvms.negotiate_parameters(&invalid_params).is_err());
    }
}
