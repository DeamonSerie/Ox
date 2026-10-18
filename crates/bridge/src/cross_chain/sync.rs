//! Source-chain freshness, clock-skew, lag, and expiration validation.

use crate::cross_chain::{CrossChainError, CrossChainResult};
use oxydome_core::BlockHeader;

pub const MAX_HEADER_AGE_SECS: u64 = 60;
pub const MAX_STALE_HEADER_AGE_SECS: u64 = 300;
pub const MAX_FUTURE_SKEW_SECS: u64 = 60;
pub const MAX_SYNC_LAG_BLOCKS: u64 = 10;

pub fn validate_header_timestamp(header: &BlockHeader, now_secs: u64) -> CrossChainResult<()> {
    if header.timestamp / 1000 > now_secs.saturating_add(MAX_FUTURE_SKEW_SECS) {
        return Err(CrossChainError::BlockFromFuture(header.timestamp));
    }
    let age = now_secs.saturating_sub(header.timestamp / 1000);
    if age > MAX_STALE_HEADER_AGE_SECS {
        return Err(CrossChainError::BlockTooOld(age, MAX_STALE_HEADER_AGE_SECS));
    }
    Ok(())
}

pub fn validate_sync_lag(local_height: u64, source_height: u64) -> CrossChainResult<()> {
    if local_height > source_height && local_height - source_height > MAX_SYNC_LAG_BLOCKS {
        return Err(CrossChainError::ChainSyncLag(local_height - source_height));
    }
    Ok(())
}

pub fn validate_expiration(expiration_millis: u64, now_millis: u64) -> CrossChainResult<()> {
    if expiration_millis != 0 && now_millis > expiration_millis {
        return Err(CrossChainError::Expired(expiration_millis));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxydome_core::{BlockHeader, PublicKey, ValueIndex};
    use oxydome_crypto::Hash;

    fn header(timestamp: u64) -> BlockHeader {
        BlockHeader {
            height: 1,
            execution_version: 1,
            ovm_activation_height: 0,
            smart_contract_activation_height: 0,
            prev_hash: Hash::zero(),
            tx_root: Hash::zero(),
            operation_root: Hash::zero(),
            ovm_receipt_root: Hash::zero(),
            utxo_root: Hash::zero(),
            state_root: Hash::zero(),
            supply: 0,
            epoch: 0,
            generation: 0,
            value_index: ValueIndex::from_raw(0),
            producer: PublicKey([0; 32]),
            timestamp,
            volume: 0,
            tx_count: 0,
            exit_amount: 0,
            ephemeral_public_key: None,
            previous_verification_commitment: None,
            verification_state_commitment: None,
            speedometer_minted: 0,
            speedometer_airdrop_amount: 0,
            gas_price: 0,
            total_gas_fees: 0,
            coin_toss_seed: None,
            ordered_tx_root: None,
        }
    }

    #[test]
    fn stale_and_future_headers_are_rejected() {
        assert!(validate_header_timestamp(&header(1_000), 1_400).is_err());
        assert!(validate_header_timestamp(&header(2_000_000), 1_000).is_err());
    }

    #[test]
    fn lag_and_expiration_are_checked() {
        assert!(validate_sync_lag(11, 0).is_err());
        assert!(validate_sync_lag(10, 0).is_ok());
        assert!(validate_expiration(10, 11).is_err());
        assert!(validate_expiration(0, 11).is_ok());
    }
}
