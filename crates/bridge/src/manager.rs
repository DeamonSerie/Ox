pub const PERCENTAGE_SERVER: u64 = 30;
pub const PERCENTAGE_MASTER: u64 = 30;
pub const PERCENTAGE_BRIDGER: u64 = 40;

#[derive(Debug, Clone, ::serde::Serialize, ::serde::Deserialize)]
pub struct WorkTokenDistribution {
    pub server_amount: u64,
    pub master_amount: u64,
    pub burn_amount: u64,
    pub bridger_amount: u64,
    pub total_amount: u64,
}

#[derive(Debug, Clone, ::serde::Serialize, ::serde::Deserialize)]
pub struct MicroTokenDistribution {
    pub bridge_id: u64,
    pub server_recipient: String,
    pub master_recipient: String,
    pub bridger_recipient: String,
    pub burn_address: String,
    pub total_supply: u64,
}

use ::serde::Serialize;
use ::serde::Deserialize;

use crate::state::{BridgeError, BridgeState};

pub struct MicroTokenManager;

impl MicroTokenManager {
    pub fn distribute_tokens(total_amount: u64) -> WorkTokenDistribution {
        let server_amount = (total_amount * PERCENTAGE_SERVER) / 100;
        let master_amount = (total_amount * PERCENTAGE_MASTER) / 100;
        let bridger_amount = (total_amount * PERCENTAGE_BRIDGER) / 100;
        let burn_amount: u64 = 0;

        WorkTokenDistribution {
            server_amount,
            master_amount,
            burn_amount,
            bridger_amount,
            total_amount,
        }
    }

    pub fn mint_work_tokens(
        bridge_id: u64,
        server_recipient: &str,
        master_recipient: &str,
        bridger_recipient: &str,
        burn_address: &str,
        total_amount: u64,
    ) -> Result<MicroTokenDistribution, crate::state::BridgeError> {
        let distribution = Self::distribute_tokens(total_amount);
        Ok(MicroTokenDistribution {
            bridge_id,
            server_recipient: server_recipient.to_string(),
            master_recipient: master_recipient.to_string(),
            bridger_recipient: bridger_recipient.to_string(),
            burn_address: burn_address.to_string(),
            total_supply: total_amount,
        })
    }

    pub fn validate_distribution(
        total_amount: u64,
        server_amount: u64,
        master_amount: u64,
        burn_amount: u64,
        bridger_amount: u64,
    ) -> bool {
        let expected_server = (total_amount * PERCENTAGE_SERVER) / 100;
        let expected_master = (total_amount * PERCENTAGE_MASTER) / 100;
        let expected_bridger = (total_amount * PERCENTAGE_BRIDGER) / 100;
        let burn_ok = burn_amount == 0;
        let totals_ok = (server_amount + master_amount + burn_amount + bridger_amount) == total_amount;

        server_amount == expected_server &&
        master_amount == expected_master &&
        bridger_amount == expected_bridger &&
        burn_ok &&
        totals_ok
    }
}
