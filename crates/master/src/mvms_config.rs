use oxydome_core::{Amount, ChainParams, GenesisAllocation, GenesisConfig, PublicKey};
use oxydome_gas::validate_currency_symbol;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Configuration for a Master Virtual Machine Starter (MVMS) node.
/// Allows developers to create customized Ox-like blockchains with
/// renamed currencies and chain-specific parameters.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MvmsConfig {
    /// Human-readable chain name (replaces "Ox" in identifiers)
    pub chain_name: String,
    /// Currency symbol token (replaces "OX" in mint/burn/gas operations)
    pub currency_symbol: String,
    /// Total currency created at genesis
    pub genesis_supply: u64,
    /// Block time in seconds
    pub block_time_seconds: u64,
    /// Master approval threshold for price changes (bps denominator base)
    pub price_update_threshold: u32,
    /// Maximum basis points change allowed per price update interval
    pub price_change_limit_bps: u32,
    /// Weighted average smoothing factor for price changes
    pub price_smoothing_bps: u32,
    /// Height at which price updates become active
    pub price_update_height: u64,
    /// GAS activation height
    pub gas_activation_height: u64,
    /// Server fee bps (share of reward converted to GAS)
    pub gas_server_fee_bps: u32,
    /// Airdrop interval in blocks
    pub airdrop_interval_blocks: u64,
    /// Base airdrop size as bps of circulating supply
    pub airdrop_base_bps: u32,
    /// Ox price oracle reference (scaled to currency)
    pub ox_price_reference: u64,
    /// BFT commit super-majority numerator
    pub bft_num: usize,
    /// BFT commit super-majority denominator
    pub bft_den: usize,
    /// Master approval super-majority numerator
    pub master_approval_num: usize,
    /// Master approval super-majority denominator
    pub master_approval_den: usize,
    /// Server-node withdrawal approval numerator
    pub node_approval_num: usize,
    /// Server-node withdrawal approval denominator
    pub node_approval_den: usize,
    /// Activity term weight alpha (bps)
    pub alpha_bps: u32,
    /// Activity term weight beta (bps)
    pub beta_bps: u32,
    /// Activity term weight gamma (bps)
    pub gamma_bps: u32,
    /// Exit pressure sensitivity eta (bps)
    pub eta_bps: u32,
    /// EMA smoothing lambda (bps)
    pub lambda_bps: u32,
    /// Reference transaction volume
    pub t_ref: u64,
    /// Reference mean transaction amount
    pub a_ref: u64,
    /// Reference exit amount
    pub e_ref: u64,
    /// Initial value index (fixed point, 1e12 == 1.000)
    #[serde(
        deserialize_with = "deserialize_u128_compat",
        serialize_with = "serialize_u128_compat"
    )]
    pub initial_value_index: u128,
    /// Value impact limit (bps)
    pub value_impact_limit_bps: u32,
    /// Mint/burn supply change limit (bps of genesis supply)
    pub supply_change_limit_bps: u32,
    /// Fee affordability coefficient rho (bps)
    pub fee_affordability_bps: u32,
    /// Smallest meaningful transaction amount A_min
    pub min_tx_amount: u64,
    /// Maximum server withdrawal per epoch (bps of genesis supply)
    pub withdraw_limit_bps: u32,
    /// Per-account withdrawal limit (bps of balance)
    pub per_account_withdraw_bps: u32,
    /// Base fee per transaction at value index 1.000
    pub base_fee: u64,

    // ---- block rewards (minted Ox) ----
    /// Base server node reward per block, in Ox
    pub server_base_reward: u64,
    /// Base master node reward per block, in Ox
    pub master_base_reward: u64,
    /// GAS price derivative sensitivity for server rewards (bps per 1% price change)
    pub gas_derivative_sensitivity_bps: u32,
    /// Master reward sensitivity to server reward derivative (bps per 1% change)
    pub master_derivative_sensitivity_bps: u32,
    /// Maximum adjustment cap for server rewards from derivatives (bps)
    pub server_reward_cap_bps: u32,
    /// Maximum adjustment cap for master rewards from derivatives (bps)
    pub master_reward_cap_bps: u32,
    /// Minimum blocks between price updates for derivative calculation
    pub min_price_update_interval: u64,
    /// Whether minted block rewards are active
    pub block_rewards_enabled: bool,
}

impl fmt::Display for MvmsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MVMS Config: chain={}, currency={}, supply={}, block_time={}s",
            self.chain_name, self.currency_symbol, self.genesis_supply, self.block_time_seconds
        )
    }
}

fn serialize_u128_compat<S>(val: &u128, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    if serializer.is_human_readable() {
        if let Ok(as_u64) = u64::try_from(*val) {
            serializer.serialize_u64(as_u64)
        } else {
            serializer.serialize_str(&val.to_string())
        }
    } else {
        serializer.serialize_u128(*val)
    }
}

fn deserialize_u128_compat<'de, D>(deserializer: D) -> Result<u128, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct U128Visitor;
    impl<'de> serde::de::Visitor<'de> for U128Visitor {
        type Value = u128;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a u128 integer or string")
        }

        fn visit_u64<E>(self, v: u64) -> Result<u128, E> {
            Ok(v as u128)
        }

        fn visit_i64<E>(self, v: i64) -> Result<u128, E>
        where
            E: serde::de::Error,
        {
            if v < 0 {
                Err(serde::de::Error::custom("expected non-negative value"))
            } else {
                Ok(v as u128)
            }
        }

        fn visit_u128<E>(self, v: u128) -> Result<u128, E> {
            Ok(v)
        }

        fn visit_str<E>(self, s: &str) -> Result<u128, E>
        where
            E: serde::de::Error,
        {
            s.parse().map_err(serde::de::Error::custom)
        }
    }
    deserializer.deserialize_any(U128Visitor)
}

impl Default for MvmsConfig {
    fn default() -> Self {
        Self {
            chain_name: "Ox".to_string(),
            currency_symbol: "OX".to_string(),
            genesis_supply: 10_000_000,
            block_time_seconds: 10,
            price_update_threshold: 6667,
            price_change_limit_bps: 500,
            price_smoothing_bps: 250,
            price_update_height: 1,
            gas_activation_height: 1,
            gas_server_fee_bps: 2000,
            airdrop_interval_blocks: 100,
            airdrop_base_bps: 100,
            ox_price_reference: 1,
            bft_num: 2,
            bft_den: 3,
            master_approval_num: 2,
            master_approval_den: 3,
            node_approval_num: 2,
            node_approval_den: 3,
            alpha_bps: 6000,
            beta_bps: 4000,
            gamma_bps: 5000,
            eta_bps: 500,
            lambda_bps: 1000,
            t_ref: 10000,
            a_ref: 100,
            e_ref: 10000,
            initial_value_index: 1_000_000_000_000,
            value_impact_limit_bps: 200,
            supply_change_limit_bps: 10,
            fee_affordability_bps: 100,
            min_tx_amount: 1,
            withdraw_limit_bps: 10,
            per_account_withdraw_bps: 3000,
            base_fee: 100,
            server_base_reward: 1000,
            master_base_reward: 50,
            gas_derivative_sensitivity_bps: 100,
            master_derivative_sensitivity_bps: 50,
            server_reward_cap_bps: 2000,
            master_reward_cap_bps: 1000,
            min_price_update_interval: 10,
            block_rewards_enabled: true,
        }
    }
}

impl MvmsConfig {
    /// Returns a new fluent builder for MVMS configuration
    pub fn builder() -> MvmsBuilder {
        MvmsBuilder::new()
    }

    /// Validate that the chain name and currency symbol are valid
    pub fn validate(&self) -> Result<(), String> {
        if self.chain_name.is_empty() {
            return Err("chain_name must not be empty".to_string());
        }
        if self.chain_name.len() > 64 {
            return Err("chain_name exceeds maximum length of 64 characters".to_string());
        }
        validate_currency_symbol(&self.currency_symbol)?;

        if self.genesis_supply == 0 {
            return Err("genesis_supply must be positive".to_string());
        }
        if self.block_time_seconds == 0 {
            return Err("block_time_seconds must be positive".to_string());
        }
        if self.price_update_threshold < 1 || self.price_update_threshold > 9999 {
            return Err("price_update_threshold must be 1-9999 bps".to_string());
        }
        if self.price_change_limit_bps < 1 || self.price_change_limit_bps > 9999 {
            return Err("price_change_limit_bps must be 1-9999 bps".to_string());
        }
        if self.price_smoothing_bps < 1 || self.price_smoothing_bps > 9999 {
            return Err("price_smoothing_bps must be 1-9999 bps".to_string());
        }
        if self.bft_den == 0 || self.bft_num > self.bft_den {
            return Err("bft_num must be <= bft_den".to_string());
        }
        if self.master_approval_den == 0 || self.master_approval_num > self.master_approval_den {
            return Err("master_approval_num must <= master_approval_den".to_string());
        }
        if self.node_approval_den == 0 || self.node_approval_num > self.node_approval_den {
            return Err("node_approval_num must <= node_approval_den".to_string());
        }
        Ok(())
    }

    /// Build a ChainParams from this MVMS config
    pub fn to_chain_params(&self) -> ChainParams {
        let supply = Amount::from(self.genesis_supply);
        let base_fee = Amount::from(self.base_fee);
        let min_tx_amount = Amount::from(self.min_tx_amount);
        let t_ref = Amount::from(self.t_ref);
        let a_ref = Amount::from(self.a_ref);
        let e_ref = Amount::from(self.e_ref);

        ChainParams {
            chain_name: self.chain_name.clone(),
            currency_symbol: self.currency_symbol.clone(),

            // supply and windows
            genesis_supply: supply,
            block_window: 10,
            rebound_lock_blocks: 5,
            audit_checkpoint_blocks: 100,

            // OVM activation
            ovm_activation_height: 1,
            smart_contract_activation_height: u64::MAX,

            // GAS fuel currency
            gas_activation_height: self.gas_activation_height,
            gas_server_fee_bps: self.gas_server_fee_bps,
            airdrop_interval_blocks: self.airdrop_interval_blocks,
            airdrop_base_bps: self.airdrop_base_bps,
            ox_price_reference: Amount::from(self.ox_price_reference),

            // price oracle
            price_update_height: self.price_update_height,
            price_update_threshold: self.price_update_threshold,
            price_change_limit_bps: self.price_change_limit_bps,
            price_smoothing_bps: self.price_smoothing_bps,

            // fee split
            fee_master_bps: 400,

            // consensus thresholds
            bft_num: self.bft_num,
            bft_den: self.bft_den,
            master_approval_num: self.master_approval_num,
            master_approval_den: self.master_approval_den,
            node_approval_num: self.node_approval_num,
            node_approval_den: self.node_approval_den,

            // currency index
            alpha_bps: self.alpha_bps,
            beta_bps: self.beta_bps,
            gamma_bps: self.gamma_bps,
            eta_bps: self.eta_bps,
            lambda_bps: self.lambda_bps,
            t_ref,
            a_ref,
            e_ref,
            initial_value_index: self.initial_value_index,

            // guardrails
            value_impact_limit_bps: self.value_impact_limit_bps,
            supply_change_limit_bps: self.supply_change_limit_bps,
            fee_affordability_bps: self.fee_affordability_bps,
            min_tx_amount,
            withdraw_limit_bps: self.withdraw_limit_bps,
            per_account_withdraw_bps: self.per_account_withdraw_bps,
            base_fee,

            // block rewards (minted Ox)
            server_base_reward: Amount::from(self.server_base_reward),
            master_base_reward: Amount::from(self.master_base_reward),
            gas_derivative_sensitivity_bps: self.gas_derivative_sensitivity_bps,
            master_derivative_sensitivity_bps: self.master_derivative_sensitivity_bps,
            server_reward_cap_bps: self.server_reward_cap_bps,
            master_reward_cap_bps: self.master_reward_cap_bps,
            min_price_update_interval: self.min_price_update_interval,
            block_rewards_enabled: self.block_rewards_enabled,
        }
    }

    /// Build a GenesisConfig with given masters and nodes
    pub fn to_genesis_config(&self, masters: Vec<PublicKey>, nodes: Vec<PublicKey>) -> GenesisConfig {
        let params = self.to_chain_params();
        let recipient = masters
            .first()
            .copied()
            .unwrap_or_else(|| PublicKey::from([1u8; 32]));
        let allocations = vec![GenesisAllocation {
            recipient,
            amount: params.genesis_supply,
        }];
        GenesisConfig {
            params,
            allocations,
            masters,
            nodes,
            timestamp: 0,
        }
    }

    /// Create an MvmsConfig from TOML string
    pub fn from_toml(toml_str: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(toml_str)
    }

    /// Create an MvmsConfig from JSON string
    pub fn from_json(json_str: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json_str)
    }

    /// Create an MvmsConfig from YAML-like key-value or JSON string
    pub fn from_yaml(yaml_str: &str) -> Result<Self, MvmsError> {
        let trimmed = yaml_str.trim();
        if trimmed.starts_with('{') {
            return Self::from_json(trimmed).map_err(MvmsError::Json);
        }

        let mut config = Self::default();
        for line in yaml_str.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((key, val)) = line.split_once(':') {
                let key = key.trim();
                let val = val.trim().trim_matches(|c| c == '\'' || c == '"');
                match key {
                    "chain_name" => config.chain_name = val.to_string(),
                    "currency_symbol" => config.currency_symbol = val.to_string(),
                    "genesis_supply" => {
                        config.genesis_supply = val.parse().map_err(|e| {
                            MvmsError::Validation(format!("Invalid genesis_supply: {}", e))
                        })?
                    }
                    "block_time_seconds" => {
                        config.block_time_seconds = val.parse().map_err(|e| {
                            MvmsError::Validation(format!("Invalid block_time_seconds: {}", e))
                        })?
                    }
                    "price_update_threshold" | "price_update_threshold_bps" => {
                        config.price_update_threshold = val.parse().map_err(|e| {
                            MvmsError::Validation(format!("Invalid price_update_threshold: {}", e))
                        })?
                    }
                    "price_change_limit_bps" => {
                        config.price_change_limit_bps = val.parse().map_err(|e| {
                            MvmsError::Validation(format!("Invalid price_change_limit_bps: {}", e))
                        })?
                    }
                    "price_smoothing_bps" => {
                        config.price_smoothing_bps = val.parse().map_err(|e| {
                            MvmsError::Validation(format!("Invalid price_smoothing_bps: {}", e))
                        })?
                    }
                    "gas_activation_height" => {
                        config.gas_activation_height = val.parse().map_err(|e| {
                            MvmsError::Validation(format!("Invalid gas_activation_height: {}", e))
                        })?
                    }
                    "base_fee" => {
                        config.base_fee = val.parse().map_err(|e| {
                            MvmsError::Validation(format!("Invalid base_fee: {}", e))
                        })?
                    }
                    _ => {}
                }
            }
        }
        config.validate().map_err(MvmsError::Validation)?;
        Ok(config)
    }
}

/// Pre-defined chain profiles for common use cases
pub mod profiles {
    use super::*;

    /// The "Custom" profile: fully customizable chain with specified currency
    pub fn custom(chain_name: &str, currency: &str, supply: u64) -> MvmsConfig {
        MvmsConfig {
            chain_name: chain_name.to_string(),
            currency_symbol: currency.to_string(),
            genesis_supply: supply,
            ..Default::default()
        }
    }

    /// The "TestNet" profile: quick test chain
    pub fn testnet() -> MvmsConfig {
        MvmsConfig {
            chain_name: "TestOx".to_string(),
            currency_symbol: "TOX".to_string(),
            genesis_supply: 1_000_000,
            block_time_seconds: 5,
            ..Default::default()
        }
    }

    /// The "DevNet" profile: development chain with high supply
    pub fn devnet() -> MvmsConfig {
        MvmsConfig {
            chain_name: "DevOx".to_string(),
            currency_symbol: "DOX".to_string(),
            genesis_supply: 100_000_000,
            block_time_seconds: 1,
            ..Default::default()
        }
    }
}

/// A result type for MVMS operations
pub type MvmsResult<T> = std::result::Result<T, MvmsError>;

#[derive(Debug, thiserror::Error)]
pub enum MvmsError {
    #[error("Validation error: {0}")]
    Validation(String),
    #[error("YAML parsing error: {0}")]
    Yaml(String),
    #[error("TOML parsing error: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("JSON parsing error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Unsupported operation")]
    Unsupported,
}

/// DSL builder for MvmsConfig
#[derive(Debug, Clone, Default)]
pub struct MvmsBuilder {
    config: MvmsConfig,
}

impl MvmsBuilder {
    pub fn new() -> Self {
        Self {
            config: MvmsConfig::default(),
        }
    }

    pub fn chain_name(mut self, name: &str) -> Self {
        self.config.chain_name = name.to_string();
        self
    }

    pub fn currency_symbol(mut self, symbol: &str) -> Self {
        self.config.currency_symbol = symbol.to_string();
        self
    }

    pub fn genesis_supply(mut self, supply: u64) -> Self {
        self.config.genesis_supply = supply;
        self
    }

    pub fn block_time(mut self, seconds: u64) -> Self {
        self.config.block_time_seconds = seconds;
        self
    }

    pub fn price_update_threshold(mut self, bps: u32) -> Self {
        self.config.price_update_threshold = bps;
        self
    }

    pub fn price_change_limit(mut self, bps: u32) -> Self {
        self.config.price_change_limit_bps = bps;
        self
    }

    pub fn price_smoothing(mut self, bps: u32) -> Self {
        self.config.price_smoothing_bps = bps;
        self
    }

    pub fn gas_activation(mut self, height: u64) -> Self {
        self.config.gas_activation_height = height;
        self
    }

    pub fn base_fee(mut self, fee: u64) -> Self {
        self.config.base_fee = fee;
        self
    }

    pub fn server_base_reward(mut self, reward: u64) -> Self {
        self.config.server_base_reward = reward;
        self
    }

    pub fn master_base_reward(mut self, reward: u64) -> Self {
        self.config.master_base_reward = reward;
        self
    }

    pub fn gas_derivative_sensitivity(mut self, bps: u32) -> Self {
        self.config.gas_derivative_sensitivity_bps = bps;
        self
    }

    pub fn master_derivative_sensitivity(mut self, bps: u32) -> Self {
        self.config.master_derivative_sensitivity_bps = bps;
        self
    }

    pub fn server_reward_cap(mut self, bps: u32) -> Self {
        self.config.server_reward_cap_bps = bps;
        self
    }

    pub fn master_reward_cap(mut self, bps: u32) -> Self {
        self.config.master_reward_cap_bps = bps;
        self
    }

    pub fn min_price_update_interval(mut self, blocks: u64) -> Self {
        self.config.min_price_update_interval = blocks;
        self
    }

    pub fn block_rewards_enabled(mut self, enabled: bool) -> Self {
        self.config.block_rewards_enabled = enabled;
        self
    }

    pub fn build(self) -> MvmsResult<MvmsConfig> {
        self.config
            .validate()
            .map_err(MvmsError::Validation)?;
        Ok(self.config)
    }
}

/// Parse MvmsConfig from YAML file path
pub fn from_yaml_file(path: &std::path::Path) -> MvmsResult<MvmsConfig> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| MvmsError::Validation(format!("Failed to read {}: {}", path.display(), e)))?;
    MvmsConfig::from_yaml(&content)
}

/// Parse MvmsConfig from TOML file path
pub fn from_toml_file(path: &std::path::Path) -> MvmsResult<MvmsConfig> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| MvmsError::Validation(format!("Failed to read {}: {}", path.display(), e)))?;
    MvmsConfig::from_toml(&content).map_err(MvmsError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mvms_builder() {
        let config = MvmsConfig::builder()
            .chain_name("AetherChain")
            .currency_symbol("AETH")
            .genesis_supply(25_000_000)
            .block_time(12)
            .price_update_threshold(7000)
            .price_change_limit(400)
            .price_smoothing(300)
            .gas_activation(5)
            .base_fee(150)
            .build()
            .expect("valid builder build");

        assert_eq!(config.chain_name, "AetherChain");
        assert_eq!(config.currency_symbol, "AETH");
        assert_eq!(config.genesis_supply, 25_000_000);
        assert_eq!(config.block_time_seconds, 12);
        assert_eq!(config.price_update_threshold, 7000);
        assert_eq!(config.base_fee, 150);

        let params = config.to_chain_params();
        assert_eq!(params.chain_name, "AetherChain");
        assert_eq!(params.currency_symbol, "AETH");
        assert_eq!(params.genesis_supply, 25_000_000);
    }

    #[test]
    fn test_from_yaml_dsl() {
        let yaml = r#"
# Custom test chain
chain_name: "MyChain"
currency_symbol: "MYGAS"
genesis_supply: 5000000
block_time_seconds: 10
price_update_threshold_bps: 6667
price_change_limit_bps: 500
price_smoothing_bps: 250
"#;
        let config = MvmsConfig::from_yaml(yaml).expect("parse yaml dsl");
        assert_eq!(config.chain_name, "MyChain");
        assert_eq!(config.currency_symbol, "MYGAS");
        assert_eq!(config.genesis_supply, 5_000_000);
        assert_eq!(config.block_time_seconds, 10);
        assert_eq!(config.price_update_threshold, 6667);
        assert_eq!(config.price_change_limit_bps, 500);
        assert_eq!(config.price_smoothing_bps, 250);
    }

    #[test]
    fn test_from_toml() {
        let toml_str = r#"
chain_name = "TomlChain"
currency_symbol = "TOMLX"
genesis_supply = 8000000
block_time_seconds = 8
price_update_threshold = 6000
price_change_limit_bps = 450
price_smoothing_bps = 200
price_update_height = 1
gas_activation_height = 1
gas_server_fee_bps = 2000
airdrop_interval_blocks = 100
airdrop_base_bps = 100
ox_price_reference = 1
bft_num = 2
bft_den = 3
master_approval_num = 2
master_approval_den = 3
node_approval_num = 2
node_approval_den = 3
alpha_bps = 6000
beta_bps = 4000
gamma_bps = 5000
eta_bps = 500
lambda_bps = 1000
t_ref = 10000
a_ref = 100
e_ref = 10000
initial_value_index = 1000000000000
value_impact_limit_bps = 200
supply_change_limit_bps = 10
fee_affordability_bps = 100
min_tx_amount = 1
withdraw_limit_bps = 10
per_account_withdraw_bps = 3000
base_fee = 100
server_base_reward = 1000
master_base_reward = 50
gas_derivative_sensitivity_bps = 100
master_derivative_sensitivity_bps = 50
server_reward_cap_bps = 2000
master_reward_cap_bps = 1000
min_price_update_interval = 10
block_rewards_enabled = true
"#;
        let config = MvmsConfig::from_toml(toml_str).expect("parse toml");
        assert_eq!(config.chain_name, "TomlChain");
        assert_eq!(config.currency_symbol, "TOMLX");
        assert_eq!(config.genesis_supply, 8_000_000);
    }

    #[test]
    fn test_validation_errors() {
        let mut cfg = MvmsConfig::default();
        cfg.chain_name = "".to_string();
        assert!(cfg.validate().is_err());

        let mut cfg2 = MvmsConfig::default();
        cfg2.currency_symbol = "INVALID-SYM!".to_string();
        assert!(cfg2.validate().is_err());

        let mut cfg3 = MvmsConfig::default();
        cfg3.genesis_supply = 0;
        assert!(cfg3.validate().is_err());

        let mut cfg4 = MvmsConfig::default();
        cfg4.block_time_seconds = 0;
        assert!(cfg4.validate().is_err());
    }
}