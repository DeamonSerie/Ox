//! Oxydome wallet core.
//!
//! Everything a wallet app needs that is independent of any network transport:
//!
//! * `address` — `ox1…` bech32m addresses over the 32-byte Ed25519 public key;
//! * `fee` — the `0.0012%` of output-amount fee rule (`max(1, ceil(sum(outputs) * 12 / 1e6))`);
//! * `coinselect` — UTXO selection with change and a fixed-point fee solver;
//! * `builder` — turning a selection into an unsigned `Transaction` plus signing helpers;
//! * `sign` — the domain-separated message-signing scheme (`ox_signMessage`, `ox_signTypedData`)
//!   that is disjoint from transaction sighashing;
//! * `keys` — the `Signer` abstraction so wallet apps can sign with a local keypair, a remote
//!   signer, or the optional (M13) vault.
//!
//! This crate holds no keys and performs no I/O by default: it is the non-custodial core that
//! `oxydome-walletd` and Rust wallet developers build on.

pub mod address;
pub mod builder;
pub mod coinselect;
pub mod fee;
pub mod keys;
pub mod sign;

use thiserror::Error;

/// Errors produced by the wallet core.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum WalletError {
    #[error("address error: {0}")]
    Address(String),
    #[error("amount is zero")]
    ZeroAmount,
    #[error(
        "no spendable UTXO covers the requested amount (needed {needed}, available {available})"
    )]
    InsufficientFunds { needed: u128, available: u128 },
    #[error("transaction requires more than {0} inputs")]
    TooManyInputs(usize),
    #[error("fee solver did not converge")]
    FeeNotConverged,
    #[error("built transaction violates conservation (inputs {inputs} != outputs {outputs} + fee {fee})")]
    Conservation {
        inputs: u128,
        outputs: u128,
        fee: u128,
    },
    #[error("message signing error: {0}")]
    Signing(String),
    #[error("core error: {0}")]
    Core(#[from] oxydome_core::CoreError),
    #[error("transaction error: {0}")]
    Tx(#[from] oxydome_core::TxError),
}
