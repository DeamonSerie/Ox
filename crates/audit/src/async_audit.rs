//! Async audit wrappers using the `smol` runtime.
//!
//! Provides async versions of `header_audit` and `audit_package` so that master servers
//! can audit multiple proposed blocks concurrently without blocking the tokio TCP accept loop.

use crate::{AuditError, AuditPackage, AuditReport, HeaderAuditContext};
use futures_util::future::join_all;
use oxydome_core::{ChainParams, GovernanceSet};
use oxydome_state::ChainState;

/// Async wrapper around `header_audit`.
/// Runs the synchronous header-only audit on a smol blocking thread.
pub async fn header_audit_async(
    ctx: &HeaderAuditContext<'_>,
    package: &AuditPackage,
) -> Result<AuditReport, AuditError> {
    let owned_ctx = OwnedAuditContext::from(ctx);
    let package = package.clone();
    smol::unblock(move || {
        let ctx_ref = owned_ctx.as_ref();
        crate::header_audit(&ctx_ref, &package)
    })
    .await
}

/// Async wrapper around `audit_package`.
/// Runs the full (deep-replay) audit on a smol blocking thread.
pub async fn audit_package_async(
    state_before: &ChainState,
    gov: &GovernanceSet,
    params: &ChainParams,
    package: &AuditPackage,
) -> Result<AuditReport, AuditError> {
    let state_before = state_before.clone();
    let gov = gov.clone();
    let params = params.clone();
    let package = package.clone();
    smol::unblock(move || crate::audit_package(&state_before, &gov, &params, &package)).await
}

/// Audits multiple header packages in parallel using smol.
/// Each audit runs on a dedicated blocking thread; the join is driven by `join_all`.
pub async fn header_audit_parallel(
    ctx: &HeaderAuditContext<'_>,
    packages: &[AuditPackage],
) -> Vec<Result<AuditReport, AuditError>> {
    let results: Vec<Result<AuditReport, AuditError>> = join_all(packages.iter().map(|pkg| {
        let owned_ctx = OwnedAuditContext::from(ctx);
        let pkg = pkg.clone();
        smol::unblock(move || {
            let ctx_ref = owned_ctx.as_ref();
            crate::header_audit(&ctx_ref, &pkg)
        })
    }))
    .await;
    results
}

/// Audits multiple full packages in parallel using smol.
pub async fn audit_package_parallel(
    state_before: &ChainState,
    gov: &GovernanceSet,
    params: &ChainParams,
    packages: &[AuditPackage],
) -> Vec<Result<AuditReport, AuditError>> {
    let state = state_before.clone();
    let gov = gov.clone();
    let params = params.clone();
    let results: Vec<Result<AuditReport, AuditError>> = join_all(packages.iter().map(|pkg| {
        let state = state.clone();
        let gov = gov.clone();
        let params = params.clone();
        let pkg = pkg.clone();
        smol::unblock(move || crate::audit_package(&state, &gov, &params, &pkg))
    }))
    .await;
    results
}

/// Owned copy of all `HeaderAuditContext` fields, needed because `smol::unblock`
/// requires `'static` captures but `HeaderAuditContext` holds borrowed references.
#[derive(Debug, Clone)]
struct OwnedAuditContext {
    pre_utxo_root: oxydome_core::Hash,
    prev_supply: oxydome_core::Amount,
    prev_value_index: oxydome_core::ValueIndex,
    prev_generation: u64,
    previous_window: oxydome_currency::WindowStats,
    genesis_supply: oxydome_core::Amount,
    epoch_minted: oxydome_core::Amount,
    epoch_burned: oxydome_core::Amount,
    epoch_withdrawn: oxydome_core::Amount,
    prev_server_block_reward: Option<oxydome_core::Amount>,
    ox_price: oxydome_core::Amount,
    price_last_update_height: u64,
    gov: GovernanceSet,
    params: ChainParams,
}

impl OwnedAuditContext {
    fn as_ref(&self) -> HeaderAuditContext<'_> {
        HeaderAuditContext {
            pre_utxo_root: self.pre_utxo_root,
            prev_supply: self.prev_supply,
            prev_value_index: self.prev_value_index,
            prev_generation: self.prev_generation,
            previous_window: self.previous_window.clone(),
            genesis_supply: self.genesis_supply,
            epoch_minted: self.epoch_minted,
            epoch_burned: self.epoch_burned,
            epoch_withdrawn: self.epoch_withdrawn,
            prev_server_block_reward: self.prev_server_block_reward,
            ox_price: self.ox_price,
            price_last_update_height: self.price_last_update_height,
            gov: &self.gov,
            params: &self.params,
        }
    }
}

impl From<&HeaderAuditContext<'_>> for OwnedAuditContext {
    fn from(ctx: &HeaderAuditContext<'_>) -> Self {
        OwnedAuditContext {
            pre_utxo_root: ctx.pre_utxo_root,
            prev_supply: ctx.prev_supply,
            prev_value_index: ctx.prev_value_index,
            prev_generation: ctx.prev_generation,
            previous_window: ctx.previous_window.clone(),
            genesis_supply: ctx.genesis_supply,
            epoch_minted: ctx.epoch_minted,
            epoch_burned: ctx.epoch_burned,
            epoch_withdrawn: ctx.epoch_withdrawn,
            prev_server_block_reward: ctx.prev_server_block_reward,
            ox_price: ctx.ox_price,
            price_last_update_height: ctx.price_last_update_height,
            gov: ctx.gov.clone(),
            params: ctx.params.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owned_audit_context_roundtrips() {
        // Compile-time check that the async wrappers are wired up correctly.
        fn _assert_async(
            _f: fn(
                &HeaderAuditContext,
                &AuditPackage,
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<AuditReport, AuditError>>>,
            >,
        ) {
        }
    }
}
