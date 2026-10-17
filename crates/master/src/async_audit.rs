//! Async master verification using the `smol` runtime.
//!
//! Wraps `MasterNode::audit` in `smol::unblock` so that the master TCP server can
//! audit multiple proposed blocks concurrently without blocking the tokio accept loop.

use crate::MasterNode;
use futures_util::future::join_all;
use oxydome_audit::{AuditAttestation, AuditError, AuditPackage};

/// Async wrapper around `MasterNode::audit`.
/// Runs the synchronous header-only audit on a smol blocking thread.
pub async fn audit_async(
    master: &MasterNode,
    package: &AuditPackage,
) -> Result<AuditAttestation, AuditError> {
    let cloned_master = master.clone();
    let package = package.clone();
    smol::unblock(move || cloned_master.audit(&package)).await
}

/// Audits multiple proposed blocks in parallel using smol.
/// Each audit runs on a dedicated blocking thread; the join is driven by `join_all`.
pub async fn audit_parallel(
    master: &MasterNode,
    packages: &[AuditPackage],
) -> Vec<Result<AuditAttestation, AuditError>> {
    let cloned_master = master.clone();
    let results: Vec<Result<AuditAttestation, AuditError>> = join_all(packages.iter().map(|pkg| {
        let master = cloned_master.clone();
        let pkg = pkg.clone();
        smol::unblock(move || master.audit(&pkg))
    }))
    .await;
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn async_functions_compile() {
        // Compile-time check that the async wrappers exist.
        fn _assert_audit_async(
            _f: fn(
                &MasterNode,
                &AuditPackage,
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<AuditAttestation, AuditError>>>,
            >,
        ) {
        }
        fn _assert_audit_parallel(
            _f: fn(
                &MasterNode,
                &[AuditPackage],
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = Vec<Result<AuditAttestation, AuditError>>>>,
            >,
        ) {
        }
    }
}
