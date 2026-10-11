//! OHM (Ox Hosted Machine) node-side engine.
//!
//! OHM creates isolated, tenant-owned blockchains that rely on Ox network nodes for their
//! immutable ledger. Each OHM is a separate blockchain whose transactions are private from the
//! Ox network and from other OHMs.
//!
//! The Ox chain commits only lightweight anchors (via [`OhmOperation`]). Server nodes keep the
//! private [`OhmBlock`] bodies and re-derive the OHM UTXO set with [`OhmLedger`], rejecting any
//! Ox block whose anchor does not match the re-derived state root.

pub use oxydome_core::ohm::{
    build_ohm_server_outputs, compute_ohm_fee_split, hash_words, ohm_cross_msg_id,
    ohm_genesis_hash, ohm_inbox_root, ohm_outbox_root, ohm_state_root, ohm_state_root_full,
    ohm_treasury_outpoint, ohm_utxo_root, reply_arguments, CrossRecvCall, CrossSendCall,
    InboundReceipt, OhmAction, OhmBlock, OhmBlockHeader, OhmContext, OhmContract, OhmInput,
    OhmOperation, OhmOutput, OhmPolicy, OhmState, OhmTransaction, OhmUtxoEntry, OutboundMessage,
    MAX_CROSS_MESSAGE_ARGS, MAX_CROSS_MESSAGE_ENTRY_BYTES, MAX_OHM_BLOCK_TXS, MAX_OHM_NAME_BYTES,
    MAX_OHM_REASON_BYTES, MAX_OHM_TX_ITEMS, OHM_POLICY_MAGIC, OHM_POLICY_VERSION,
    OHM_SERVER_FEE_BPS,
};

pub use oxydome_core::{Amount, Hash, OutPoint, OvmAction, OvmFailureCode, PublicKey, Sig};

pub mod chain;
pub mod operations;
pub mod validation;

pub use chain::{CrossChainView, OhmCallOutcome, OhmError, OhmLedger};
