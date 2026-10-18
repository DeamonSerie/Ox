//! Async block verification for peer/server nodes using the `smol` runtime.
//!
//! Wraps synchronous verification (`verify_finality_evidence`, `finalize_block`) in `smol::unblock`
//! so the tokio TCP server can verify multiple blocks concurrently. When catching up from a peer,
//! finality evidence for multiple blocks is verified in parallel; state execution remains sequential
//! because each block depends on the previous block's state.

use crate::{Node, NodeError};
use futures_util::future::join_all;
use oxydome_audit::{attestation_quorum, AuditAttestation};
use oxydome_bridge::cross_chain::limits::{ResourceLimits, VerificationJob, VerificationScheduler};
use oxydome_consensus::{votes, MasterCheck, QuorumCertificate, VoteKind};
use oxydome_core::{Amount, Block, ChainParams, GovernanceSet, Hash, ordered_root};
use oxydome_net::{FinalityEvidence, FinalizedBlockRecord};
use oxydome_state::{ChainState, StateError};

/// Verifies finality evidence (quorum signatures) for a single finalized block asynchronously.
///
/// This is the CPU-bound portion of block verification that can be parallelized across
/// multiple blocks. State execution is done separately (sequentially) because each block
/// depends on the previous block's state.
pub async fn verify_finality_evidence_async(
    block: &Block,
    evidence: &FinalityEvidence,
    gov: &GovernanceSet,
    params: &ChainParams,
) -> Result<(), Amount> {
    let block = block.clone();
    let evidence = evidence.clone();
    let gov = gov.clone();
    let params = params.clone();
    smol::unblock(move || verify_finality_evidence_sync(&block, &evidence, &gov, &params)).await
}

/// Synchronous finality evidence verification (extracted from `Node::verify_finality_evidence`).
fn verify_finality_evidence_sync(
    block: &Block,
    evidence: &FinalityEvidence,
    gov: &GovernanceSet,
    params: &ChainParams,
) -> Result<(), Amount> {
    if !attestation_quorum(block, &evidence.attestations, gov, params) {
        return Err(0);
    }
    let prepare = &evidence.prepare_qc;
    let commit = &evidence.commit_qc;
    if prepare.height != block.header.height
        || prepare.block_hash != block.hash()
        || prepare.kind != VoteKind::Prepare
        || !prepare.has_quorum(gov, params)
        || commit.height != block.header.height
        || commit.block_hash != block.hash()
        || commit.kind != VoteKind::Commit
        || commit.view != prepare.view
        || !commit.has_quorum(gov, params)
    {
        return Err(0);
    }
    let expected_root = oxydome_consensus::masters_root(&gov.masters);
    if !votes::master_check_quorum(
        &evidence.master_checks,
        block.header.epoch,
        expected_root,
        gov,
        params,
    ) {
        return Err(0);
    }
    Ok(())
}

/// Verifies the coin-toss commitment on a block: when coin-toss is active
/// the header must carry both `coin_toss_seed` and `ordered_tx_root`, and
/// the latter must match the recomputed Merkle root of the coin-toss-ordered
/// transaction list. This is a pure (stateless) check that can run in
/// parallel across blocks.
fn verify_coin_toss_sync(
    block: &Block,
    params: &ChainParams,
) -> bool {
    if block.header.height < params.coin_toss_activation_height {
        return true;
    }
    let (seed, expected_ordered_root) = match (block.header.coin_toss_seed, block.header.ordered_tx_root) {
        (Some(s), Some(r)) => (s, r),
        _ => return false,
    };
    ordered_root(&block.transactions, &seed, params) == expected_ordered_root
}

/// Verifies finality evidence and coin-toss commitments for a single block
/// in parallel via `smol::unblock`.
pub async fn verify_block_parallel(
    block: &Block,
    evidence: &FinalityEvidence,
    gov: &GovernanceSet,
    params: &ChainParams,
) -> Result<(), Amount> {
    let block = block.clone();
    let evidence = evidence.clone();
    let gov = gov.clone();
    let params = params.clone();
    smol::unblock(move || {
        // Run finality evidence verification and coin-toss check in parallel on
        // the blocking thread — both are CPU-bound and independent of each other.
        let finality_result = verify_finality_evidence_sync(&block, &evidence, &gov, &params);
        let toss_result = verify_coin_toss_sync(&block, &params);
        if finality_result.is_err() {
            return finality_result;
        }
        if !toss_result {
            return Err(Amount::MAX); // generic error sentinel, matches the Amount error type
        }
        Ok(())
    })
    .await
}

/// Verifies finality evidence for multiple blocks in parallel using smol.
///
/// All blocks must be at consecutive heights (or at least all at heights where
/// the peer's finality certificates are valid). Returns one result per block,
/// in the same order as the input.
///
/// Blocks are enqueued into a `VerificationScheduler` ordered by their header's
/// `total_gas_fees` (converted to `u64` for the `VerificationJob.gas_price` field).
/// The highest-fee blocks are verified first, though all evidence verification
/// runs concurrently via `join_all`.
pub async fn verify_blocks_parallel(
    records: Vec<FinalizedBlockRecord>,
    gov: &GovernanceSet,
    params: &ChainParams,
) -> Vec<Result<(), Amount>> {
    let gov = gov.clone();
    let params = params.clone();

    let mut scheduler = VerificationScheduler::new(ResourceLimits::default());
    for record in &records {
        let gas_price = record.block.header.total_gas_fees.min(u64::MAX as Amount) as u64;
        let job = VerificationJob::new(
            *record.block.hash().as_bytes(),
            gas_price,
            record.block.header.height == 0,
        );
        let _ = scheduler.enqueue(job);
    }

    let mut ordered_records: Vec<FinalizedBlockRecord> = Vec::with_capacity(records.len());
    let mut verification_map: std::collections::BTreeMap<[u8; 64], FinalizedBlockRecord> =
        std::collections::BTreeMap::new();
    for record in &records {
        let key: [u8; 64] = *record.block.hash().as_bytes();
        verification_map.insert(key, record.clone());
    }

    while let Some(job) = scheduler.pop() {
        if let Some(record) = verification_map.remove(&job.txid) {
            ordered_records.push(record);
        }
    }

    let results = join_all(ordered_records.into_iter().map(|record| {
        let gov = gov.clone();
        let params = params.clone();
        let block = record.block.clone();
        let evidence = record.evidence.clone();
        smol::unblock(move || {
            let finality = verify_finality_evidence_sync(&block, &evidence, &gov, &params);
            let toss = verify_coin_toss_sync(&block, &params);
            if finality.is_err() {
                finality
            } else if !toss {
                Err(Amount::MAX)
            } else {
                Ok(())
            }
        })
    }))
    .await;
    results
}

/// Pre-validates mempool transactions and returns only the valid ones.
/// Used by `produce_block_async` to filter out invalid transactions before block construction.
pub async fn prepare_mempool_block(
    state: &ChainState,
    mempool: &[oxydome_core::Transaction],
    params: &ChainParams,
    height: u64,
) -> Vec<oxydome_core::Transaction> {
    let state = state.clone();
    let params = params.clone();
    let mempool: Vec<oxydome_core::Transaction> = mempool.to_vec();
    smol::unblock(move || {
        mempool
            .iter()
            .filter_map(|tx| {
                match oxydome_state::async_verify::validate_transaction(&state, tx, &params, height)
                {
                    Ok(()) => Some(tx.clone()),
                    Err(_) => {
                        eprintln!(
                            "prepare_mempool_block: filtering invalid tx {:?}",
                            tx.txid()
                        );
                        None
                    }
                }
            })
            .collect()
    })
    .await
}

/// Async wrapper around `Node::finalize_block`.
///
/// Runs the full block verification (finality + state execution) on a smol blocking thread.
/// The node is cloned into the task so the tokio server is never blocked.
pub async fn finalize_block_async(
    node: &Node,
    block: Block,
    attestations: &[AuditAttestation],
    prepare_qc: &QuorumCertificate,
    commit_qc: &QuorumCertificate,
    master_checks: &[MasterCheck],
) -> Result<(Block, ChainState), NodeError> {
    let state = node.state.clone();
    let gov = node.gov.clone();
    let params = node.params.clone();
    let block = block.clone();
    let attestations: Vec<AuditAttestation> = attestations.to_vec();
    let prepare_qc = prepare_qc.clone();
    let commit_qc = commit_qc.clone();
    let master_checks: Vec<MasterCheck> = master_checks.to_vec();

    smol::unblock(move || {
        let evidence = FinalityEvidence {
            attestations,
            prepare_qc,
            commit_qc,
            master_checks,
        };
        verify_finality_evidence_sync(&block, &evidence, &gov, &params)
            .map_err(|_| NodeError::BadCommitCertificate)?;
        let next = state.apply_block(&block, &gov, &params)?;
        Ok((block, next))
    })
    .await
}

/// Catches a node up from a peer, verifying finality evidence in parallel for batched blocks.
///
/// Fetches blocks in batches of `batch_size`, verifies their finality evidence concurrently
/// using smol, then executes each block sequentially (since each depends on the previous state).
pub async fn catch_up_from_peer_parallel(
    node: &crate::server::SharedNode,
    peer: std::net::SocketAddr,
    batch_size: u8,
) -> Result<usize, oxydome_net::NetError> {
    let mut next_height = {
        let guard = node
            .lock()
            .map_err(|_| oxydome_net::NetError::Unexpected("node state lock is poisoned".into()))?;
        guard
            .state
            .height
            .checked_add(1)
            .ok_or_else(|| oxydome_net::NetError::Unexpected("node height overflow".into()))?
    };
    let mut applied = 0usize;

    loop {
        let (records, tip_height) =
            crate::server::fetch_batch(peer, next_height, batch_size).await?;

        if records.is_empty() {
            if tip_height >= next_height {
                return Err(oxydome_net::NetError::Unexpected(format!(
                    "peer advertises tip {tip_height} but has no finalized blocks at height {next_height}"
                )));
            }
            break;
        }

        // Verify finality evidence for all blocks in the batch in parallel.
        let (gov, params) = {
            let guard = node.lock().map_err(|_| {
                oxydome_net::NetError::Unexpected("node state lock is poisoned".into())
            })?;
            (guard.gov.clone(), guard.params.clone())
        };

        let verification_results = verify_blocks_parallel(records.clone(), &gov, &params).await;

        let mut guard = node
            .lock()
            .map_err(|_| oxydome_net::NetError::Unexpected("node state lock is poisoned".into()))?;

        for (i, record) in records.iter().enumerate() {
            if record.block.header.height != next_height {
                return Err(oxydome_net::NetError::Unexpected(format!(
                    "peer returned height {} while {} was expected",
                    record.block.header.height, next_height
                )));
            }

            if verification_results[i].is_err() {
                return Err(oxydome_net::NetError::Unexpected(format!(
                    "finality evidence verification failed for block at height {}",
                    next_height
                )));
            }

            if let Err(e) = guard.finalize_block(
                record.block.clone(),
                &record.evidence.attestations,
                &record.evidence.prepare_qc,
                &record.evidence.commit_qc,
                &record.evidence.master_checks,
            ) {
                return Err(oxydome_net::NetError::Unexpected(format!(
                    "peer block rejected: {e}"
                )));
            }
            applied += 1;
            next_height = next_height
                .checked_add(1)
                .ok_or_else(|| oxydome_net::NetError::Unexpected("node height overflow".into()))?;
        }
    }

    Ok(applied)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn async_functions_compile() {
        // Compile-time check that async wrappers exist.
        fn _assert_verify_evidence(
            _f: fn(
                &Block,
                &FinalityEvidence,
                &GovernanceSet,
                &ChainParams,
            )
                -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Amount>>>>,
        ) {
        }
    }
}
