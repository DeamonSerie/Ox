//! JSON-RPC wire types for the Oxydome wallet-makers API.
//!
//! Defines the JSON-RPC 2.0 request/response envelopes, error codes, method name constants,
//! and friendly JSON representations of chain data (transactions, blocks, receipts).
//! Shared by `oxydome-walletd` (server) and `oxydome-wallet-rpc-client` (client).

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// JSON-RPC 2.0 envelopes
// ---------------------------------------------------------------------------

/// A JSON-RPC 2.0 request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcRequest {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
    pub id: serde_json::Value,
}

impl RpcRequest {
    pub fn new(
        method: impl Into<String>,
        params: serde_json::Value,
        id: serde_json::Value,
    ) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            method: method.into(),
            params,
            id,
        }
    }
}

/// A JSON-RPC 2.0 response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcResponse {
    pub jsonrpc: String,
    pub id: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

impl RpcResponse {
    pub fn success(id: serde_json::Value, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(id: serde_json::Value, error: RpcError) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: None,
            error: Some(error),
        }
    }
}

/// A JSON-RPC 2.0 error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl RpcError {
    pub fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    pub fn with_data(code: i64, message: impl Into<String>, data: serde_json::Value) -> Self {
        Self {
            code,
            message: message.into(),
            data: Some(data),
        }
    }

    // Standard JSON-RPC error codes
    pub const INVALID_REQUEST: i64 = -32600;
    pub const METHOD_NOT_FOUND: i64 = -32601;
    pub const INVALID_PARAMS: i64 = -32602;
    pub const INTERNAL_ERROR: i64 = -32603;

    // Application-specific error codes
    pub const CUSTODIAL_DISABLED: i64 = -32000;
    pub const RESOURCE_NOT_FOUND: i64 = -32001;
    pub const RESOURCE_UNAVAILABLE: i64 = -32002;
    pub const TX_REJECTED: i64 = -32003;
    pub const METHOD_NOT_SUPPORTED: i64 = -32004;
    pub const LIMIT_EXCEEDED: i64 = -32005;
    pub const INVALID_SIGNATURE: i64 = -32006;
    pub const INSUFFICIENT_FUNDS: i64 = -32007;
    pub const INVALID_ADDRESS: i64 = -32008;
    pub const VAULT_LOCKED: i64 = -32009;
    pub const VAULT_NOT_FOUND: i64 = -32010;
}

// ---------------------------------------------------------------------------
// Method name constants
// ---------------------------------------------------------------------------

pub mod methods {
    pub const CHAIN_ID: &str = "ox_chainId";
    pub const BLOCK_NUMBER: &str = "ox_blockNumber";
    pub const GET_BALANCE: &str = "ox_getBalance";
    pub const GET_TRANSACTION_COUNT: &str = "ox_getTransactionCount";
    pub const GET_BLOCK_BY_NUMBER: &str = "ox_getBlockByNumber";
    pub const GET_BLOCK_BY_HASH: &str = "ox_getBlockByHash";
    pub const GET_TRANSACTION_BY_HASH: &str = "ox_getTransactionByHash";
    pub const GET_TRANSACTION_RECEIPT: &str = "ox_getTransactionReceipt";
    pub const GET_CODE: &str = "ox_getCode";
    pub const GET_ASSET_MANIFEST: &str = "ox_getAssetManifest";
    pub const GET_ASSET: &str = "ox_getAsset";
    pub const PUT_CONTENT: &str = "ox_putContent";
    pub const CALL: &str = "ox_call";
    pub const ESTIMATE_GAS: &str = "ox_estimateGas";
    pub const GAS_PRICE: &str = "ox_gasPrice";
    pub const FEE_HISTORY: &str = "ox_feeHistory";
    pub const GET_LOGS: &str = "ox_getLogs";
    pub const SYNCING: &str = "ox_syncing";
    pub const ACCOUNTS: &str = "ox_accounts";
    pub const REQUEST_ACCOUNTS: &str = "ox_requestAccounts";
    pub const SEND_TRANSACTION: &str = "ox_sendTransaction";
    pub const SIGN_MESSAGE: &str = "ox_signMessage";
    pub const SIGN_TYPED_DATA: &str = "ox_signTypedData";
    pub const VERIFY_MESSAGE: &str = "ox_verifyMessage";
    pub const SUBSCRIBE: &str = "ox_subscribe";
    pub const UNSUBSCRIBE: &str = "ox_unsubscribe";
    pub const GET_UTXOS: &str = "ox_getUTXOs";
    pub const GET_HISTORY: &str = "ox_getHistory";
    pub const GET_PROOF: &str = "ox_getProof";
    pub const GET_VALUE_INDEX: &str = "ox_getValueIndex";

    // Vault methods
    pub const VAULT_CREATE: &str = "ox_vaultCreate";
    pub const VAULT_IMPORT: &str = "ox_vaultImport";
    pub const VAULT_UNLOCK: &str = "ox_vaultUnlock";
    pub const VAULT_LOCK: &str = "ox_vaultLock";
    pub const VAULT_STATUS: &str = "ox_vaultStatus";
    pub const VAULT_CHANGE_PASSWORD: &str = "ox_vaultChangePassword";
    pub const VAULT_EXPORT: &str = "ox_vaultExport";
}

// ---------------------------------------------------------------------------
// Friendly JSON representations
// ---------------------------------------------------------------------------

/// A transaction in friendly JSON form (hex hashes, bech32m addresses, decimal amounts).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcTransaction {
    pub txid: String,
    pub inputs: Vec<RpcInput>,
    pub outputs: Vec<RpcOutput>,
    pub fee: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ovm_action: Option<oxydome_core::OvmAction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_height: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub position: Option<u32>,
}

/// A transaction input in friendly JSON form.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcInput {
    pub txid: String,
    pub index: u32,
    pub owner: String,
    pub signature: String,
}

/// A transaction output in friendly JSON form.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcOutput {
    pub amount: String,
    pub recipient: String,
    pub kind: String,
    pub created_height: u64,
    pub mature: bool,
}

/// A block in friendly JSON form.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcBlock {
    pub hash: String,
    pub height: u64,
    pub prev_hash: String,
    pub timestamp: u64,
    pub tx_count: u64,
    pub txids: Vec<String>,
    pub state_root: String,
    pub ovm_receipts: Vec<oxydome_core::OvmReceipt>,
    pub supply: String,
    pub producer: String,
}

/// A transaction receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcReceipt {
    pub txid: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_height: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub position: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ovm_receipt: Option<oxydome_core::OvmReceipt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ovm_gas_refund: Option<RpcOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ovm_actual_fee: Option<String>,
}

/// A balance snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcBalance {
    pub spendable: String,
    pub locked_reward: String,
    pub exit_reserve: String,
    pub height: u64,
}

/// A UTXO in friendly JSON form.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcUtxo {
    pub txid: String,
    pub index: u32,
    pub amount: String,
    pub recipient: String,
    pub kind: String,
    pub created_height: u64,
    pub mature: bool,
}

/// A history entry in friendly JSON form.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcHistoryEntry {
    pub txid: String,
    pub height: u64,
    pub block_hash: String,
    pub position: u32,
    pub in_amount: String,
    pub out_amount: String,
}

/// A value index snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcValueIndex {
    pub value_index: String,
    pub generation: u64,
    pub supply: String,
    pub height: u64,
}

/// A vault status response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcVaultStatus {
    pub locked: bool,
    pub account_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mnemonic: Option<String>,
}

/// A WebSocket notification envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsNotice {
    pub jsonrpc: String,
    pub method: String,
    pub params: WsParams,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsParams {
    pub subscription: String,
    pub result: serde_json::Value,
}

/// Subscription topic names for WebSocket notifications.
pub mod topics {
    pub const NEW_BLOCKS: &str = "newBlocks";
    pub const TX_ACCEPTED: &str = "txAccepted";
    pub const TX_CONFIRMED: &str = "txConfirmed";
    pub const TX_REJECTED: &str = "txFailed";
    pub const MEMPOOL: &str = "mempool";
    pub const BALANCE_CHANGED: &str = "balanceChanged";
}

/// Parses a hex string into bytes, returning None on invalid input.
pub fn parse_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Encodes bytes as a hex string with 0x prefix.
pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2 + 2);
    s.push_str("0x");
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Formats a u128 amount as a decimal string.
pub fn amount_to_string(amount: u128) -> String {
    amount.to_string()
}

/// Parses a decimal string into a u128 amount.
pub fn amount_from_string(s: &str) -> Option<u128> {
    s.parse().ok()
}

/// Converts a core `Transaction` into its friendly JSON representation.
pub fn tx_to_rpc(
    tx: &oxydome_core::Transaction,
    location: Option<(u64, &oxydome_core::Hash, u32)>,
) -> RpcTransaction {
    let (block_height, block_hash, position) = match location {
        Some((h, hash, pos)) => (Some(h), Some(to_hex(hash.as_bytes())), Some(pos)),
        None => (None, None, None),
    };
    RpcTransaction {
        txid: to_hex(tx.txid().as_bytes()),
        inputs: tx
            .inputs
            .iter()
            .map(|i| RpcInput {
                txid: to_hex(i.prev_out.txid.as_bytes()),
                index: i.prev_out.index,
                owner: to_hex(i.owner.as_bytes()),
                signature: to_hex(i.signature.as_bytes()),
            })
            .collect(),
        outputs: tx
            .outputs
            .iter()
            .map(|o| RpcOutput {
                amount: amount_to_string(o.amount),
                recipient: to_hex(o.recipient.as_bytes()),
                kind: match o.kind {
                    oxydome_core::OutputKind::Spendable => "spendable".into(),
                    oxydome_core::OutputKind::LockedReward => "locked_reward".into(),
                    oxydome_core::OutputKind::ExitReserve { .. } => "exit_reserve".into(),
                },
                created_height: 0,
                mature: true,
            })
            .collect(),
        fee: amount_to_string(tx.fee),
        ovm_action: tx.ovm_action.clone(),
        block_height,
        block_hash,
        position,
    }
}

/// Converts a core `Block` into its friendly JSON representation.
pub fn block_to_rpc(block: &oxydome_core::Block) -> RpcBlock {
    RpcBlock {
        hash: to_hex(block.hash().as_bytes()),
        height: block.header.height,
        prev_hash: to_hex(block.header.prev_hash.as_bytes()),
        timestamp: block.header.timestamp,
        tx_count: block.header.tx_count,
        txids: block
            .transactions
            .iter()
            .map(|t| to_hex(t.txid().as_bytes()))
            .collect(),
        state_root: to_hex(block.header.state_root.as_bytes()),
        ovm_receipts: block.ovm_receipts.clone(),
        supply: amount_to_string(block.header.supply),
        producer: to_hex(block.header.producer.as_bytes()),
    }
}

/// Converts a `BalanceInfo` into its friendly JSON representation.
pub fn balance_to_rpc(info: &oxydome_net::BalanceInfo) -> RpcBalance {
    RpcBalance {
        spendable: amount_to_string(info.spendable),
        locked_reward: amount_to_string(info.locked_reward),
        exit_reserve: amount_to_string(info.exit_reserve),
        height: info.height,
    }
}

/// Converts a `TxStatus` into its friendly JSON representation.
pub fn status_to_rpc(status: &oxydome_net::TxStatus) -> RpcReceipt {
    let (status_str, block_height, block_hash, position, reason) = match status {
        oxydome_net::TxStatus::Pending => ("pending".into(), None, None, None, None),
        oxydome_net::TxStatus::Confirmed { height } => {
            ("confirmed".into(), Some(*height), None, None, None)
        }
        oxydome_net::TxStatus::Rejected { reason } => {
            ("rejected".into(), None, None, None, Some(reason.clone()))
        }
        oxydome_net::TxStatus::Unknown => ("unknown".into(), None, None, None, None),
    };
    RpcReceipt {
        txid: String::new(),
        status: status_str,
        block_height,
        block_hash,
        position,
        reason,
        ovm_receipt: None,
        ovm_gas_refund: None,
        ovm_actual_fee: None,
    }
}

/// Converts a `UtxoInfo` into its friendly JSON representation.
pub fn utxo_to_rpc(info: &oxydome_net::UtxoInfo) -> RpcUtxo {
    RpcUtxo {
        txid: to_hex(info.outpoint.txid.as_bytes()),
        index: info.outpoint.index,
        amount: amount_to_string(info.amount),
        recipient: to_hex(info.recipient.as_bytes()),
        kind: match info.kind {
            oxydome_core::OutputKind::Spendable => "spendable".into(),
            oxydome_core::OutputKind::LockedReward => "locked_reward".into(),
            oxydome_core::OutputKind::ExitReserve { .. } => "exit_reserve".into(),
        },
        created_height: info.created_height,
        mature: info.mature,
    }
}

/// Converts a `HistoryEntry` into its friendly JSON representation.
pub fn history_to_rpc(entry: &oxydome_net::HistoryEntry) -> RpcHistoryEntry {
    RpcHistoryEntry {
        txid: to_hex(entry.txid.as_bytes()),
        height: entry.height,
        block_hash: to_hex(entry.block_hash.as_bytes()),
        position: entry.position,
        in_amount: amount_to_string(entry.in_amount),
        out_amount: amount_to_string(entry.out_amount),
    }
}

/// Converts a `ValueIndexInfo` into its friendly JSON representation.
pub fn value_index_to_rpc(info: &oxydome_net::ValueIndexInfo) -> RpcValueIndex {
    RpcValueIndex {
        value_index: info.value_index.to_string(),
        generation: info.generation,
        supply: amount_to_string(info.supply),
        height: info.height,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip() {
        let bytes = vec![0xde, 0xad, 0xbe, 0xef];
        let hex = to_hex(&bytes);
        assert_eq!(hex, "0xdeadbeef");
        assert_eq!(parse_hex(&hex), Some(bytes));
        assert_eq!(parse_hex("deadbeef"), Some(vec![0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(parse_hex("0x"), Some(vec![]));
        assert_eq!(parse_hex("0xgg"), None);
        assert_eq!(parse_hex("abc"), None);
    }

    #[test]
    fn amount_string_round_trip() {
        assert_eq!(amount_to_string(12345), "12345");
        assert_eq!(amount_from_string("12345"), Some(12345));
        assert_eq!(amount_from_string("abc"), None);
    }

    #[test]
    fn rpc_response_serializes() {
        let resp = RpcResponse::success(serde_json::json!(1), serde_json::json!({"ok": true}));
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"result\""));
        assert!(!json.contains("\"error\""));

        let err = RpcResponse::error(
            serde_json::json!(1),
            RpcError::new(RpcError::METHOD_NOT_FOUND, "method not found"),
        );
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("\"error\""));
        assert!(!json.contains("\"result\""));
    }
}
