//! HTTP and WebSocket client for the Oxydome `walletd` JSON-RPC service.
//!
//! Provides a typed Rust interface to all `ox_*` methods over HTTP (POST `/`) and
//! WebSocket (GET `/ws`) transports. See PLAN.md §12.

use anyhow::{anyhow, Context, Result};
use futures_util::{SinkExt, StreamExt};
use oxydome_wallet_rpc::{methods, parse_hex, RpcError, RpcRequest, RpcResponse, WsNotice};
use serde_json::Value;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

/// HTTP client for the walletd JSON-RPC service.
pub struct WalletRpcClient {
    url: String,
    client: reqwest::Client,
}

impl WalletRpcClient {
    /// Creates a client targeting `addr` (e.g. `127.0.0.1:8545`).
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            url: format!("http://{addr}"),
            client: reqwest::Client::new(),
        }
    }

    /// Creates a client targeting a specific URL.
    pub fn with_url(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            client: reqwest::Client::new(),
        }
    }

    /// Sends a JSON-RPC request and returns the result.
    pub async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let req = RpcRequest::new(method, params, Value::Null);
        let resp: RpcResponse = self
            .client
            .post(&self.url)
            .json(&req)
            .send()
            .await
            .context("request failed")?
            .json()
            .await
            .context("invalid response")?;
        if let Some(err) = resp.error {
            return Err(anyhow!("JSON-RPC error {}: {}", err.code, err.message));
        }
        resp.result.ok_or_else(|| anyhow!("no result in response"))
    }

    /// Returns the chain ID.
    pub async fn chain_id(&self) -> Result<String> {
        self.call(methods::CHAIN_ID, Value::Null)
            .await
            .map(|v| v.as_str().unwrap_or("0x0").to_string())
    }

    /// Returns the current block height.
    pub async fn block_number(&self) -> Result<u64> {
        self.call(methods::BLOCK_NUMBER, Value::Null)
            .await
            .and_then(|v| v.as_u64().context("invalid block number"))
    }

    /// Returns the balance for `address`.
    pub async fn get_balance(&self, address: &str) -> Result<Value> {
        self.call(methods::GET_BALANCE, serde_json::json!([address]))
            .await
    }

    /// Returns the transaction count for `address` (always 0 for UTXO chains).
    pub async fn get_transaction_count(&self, address: &str) -> Result<u64> {
        self.call(methods::GET_TRANSACTION_COUNT, serde_json::json!([address]))
            .await
            .and_then(|v| v.as_u64().context("invalid count"))
    }

    /// Returns the block at `height`.
    pub async fn get_block_by_number(&self, height: u64) -> Result<Value> {
        self.call(methods::GET_BLOCK_BY_NUMBER, serde_json::json!([height]))
            .await
    }

    /// Returns the block with `hash`.
    pub async fn get_block_by_hash(&self, hash: &str) -> Result<Value> {
        self.call(methods::GET_BLOCK_BY_HASH, serde_json::json!([hash]))
            .await
    }

    /// Returns the transaction with `txid`.
    pub async fn get_transaction_by_hash(&self, txid: &str) -> Result<Value> {
        self.call(methods::GET_TRANSACTION_BY_HASH, serde_json::json!([txid]))
            .await
    }

    /// Returns the receipt for `txid`.
    pub async fn get_transaction_receipt(&self, txid: &str) -> Result<Value> {
        self.call(methods::GET_TRANSACTION_RECEIPT, serde_json::json!([txid]))
            .await
    }

    /// Returns the code at `address` (always empty for EOAs).
    pub async fn get_code(&self, address: &str) -> Result<String> {
        self.call(methods::GET_CODE, serde_json::json!([address]))
            .await
            .map(|v| v.as_str().unwrap_or("0x").to_string())
    }

    /// Returns the current gas price (fee per unit).
    pub async fn gas_price(&self) -> Result<String> {
        self.call(methods::GAS_PRICE, Value::Null)
            .await
            .map(|v| v.as_str().unwrap_or("0").to_string())
    }

    /// Returns sync status.
    pub async fn syncing(&self) -> Result<Value> {
        self.call(methods::SYNCING, Value::Null).await
    }

    /// Returns the accounts managed by the vault.
    pub async fn accounts(&self) -> Result<Vec<String>> {
        self.call(methods::ACCOUNTS, Value::Null)
            .await
            .and_then(|v| serde_json::from_value(v).context("invalid accounts"))
    }

    /// Requests accounts (same as `accounts`).
    pub async fn request_accounts(&self) -> Result<Vec<String>> {
        self.call(methods::REQUEST_ACCOUNTS, Value::Null)
            .await
            .and_then(|v| serde_json::from_value(v).context("invalid accounts"))
    }

    /// Signs a message with the vault's default account.
    pub async fn sign_message(&self, message: &str) -> Result<String> {
        self.call(methods::SIGN_MESSAGE, serde_json::json!([message]))
            .await
            .map(|v| v.as_str().unwrap_or("").to_string())
    }

    /// Signs typed data with the vault's default account.
    pub async fn sign_typed_data(&self, typed_data: Value) -> Result<String> {
        self.call(methods::SIGN_TYPED_DATA, serde_json::json!([typed_data]))
            .await
            .map(|v| v.as_str().unwrap_or("").to_string())
    }

    /// Verifies a message signature.
    pub async fn verify_message(
        &self,
        message: &str,
        signature: &str,
        address: &str,
    ) -> Result<bool> {
        self.call(
            methods::VERIFY_MESSAGE,
            serde_json::json!([message, signature, address]),
        )
        .await
        .and_then(|v| v.as_bool().context("invalid result"))
    }

    /// Returns UTXOs for `address`.
    pub async fn get_utxos(&self, address: &str) -> Result<Value> {
        self.call(methods::GET_UTXOS, serde_json::json!([address]))
            .await
    }

    /// Returns transaction history for `address`.
    pub async fn get_history(&self, address: &str, cursor: u64, limit: u32) -> Result<Value> {
        self.call(
            methods::GET_HISTORY,
            serde_json::json!([address, cursor, limit]),
        )
        .await
    }

    /// Returns a UTXO inclusion proof.
    pub async fn get_proof(&self, txid: &str, index: u32) -> Result<Value> {
        self.call(methods::GET_PROOF, serde_json::json!([txid, index]))
            .await
    }

    /// Returns the value index snapshot.
    pub async fn get_value_index(&self) -> Result<Value> {
        self.call(methods::GET_VALUE_INDEX, Value::Null).await
    }

    /// Returns the committed state for a DAO.
    pub async fn get_dao(&self, dao_id: &str) -> Result<Value> {
        self.call(methods::GET_DAO, serde_json::json!([dao_id]))
            .await
    }

    /// Signs and submits a consensus DAO operation using the unlocked vault.
    pub async fn submit_dao_operation(
        &self,
        action: Value,
        account: Option<u32>,
    ) -> Result<String> {
        self.call(
            methods::SUBMIT_DAO_OPERATION,
            serde_json::json!({
                "action": action,
                "account": account.unwrap_or(0),
            }),
        )
        .await
        .and_then(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .context("invalid DAO operation id")
        })
    }

    /// Returns the Ox-committed anchor state for an OHM.
    pub async fn get_ohm(&self, ohm_id: &str) -> Result<Value> {
        self.call(methods::GET_OHM, serde_json::json!([ohm_id]))
            .await
    }

    /// Returns a private OHM block body by hash.
    pub async fn get_ohm_block(&self, hash: &str) -> Result<Value> {
        self.call(methods::GET_OHM_BLOCK, serde_json::json!([hash]))
            .await
    }

    /// Returns the OHM-local balance of an address within an OHM.
    pub async fn get_ohm_balance(&self, ohm_id: &str, address: &str) -> Result<Value> {
        self.call(
            methods::GET_OHM_BALANCE,
            serde_json::json!([ohm_id, address]),
        )
        .await
    }

    /// Signs and submits a consensus OHM operation using the unlocked vault.
    pub async fn submit_ohm_operation(
        &self,
        action: Value,
        account: Option<u32>,
    ) -> Result<String> {
        self.call(
            methods::SUBMIT_OHM_OPERATION,
            serde_json::json!({
                "action": action,
                "account": account.unwrap_or(0),
            }),
        )
        .await
        .and_then(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .context("invalid OHM operation id")
        })
    }

    /// Submits a private OHM block for anchoring.
    pub async fn submit_ohm_block(&self, block: Value) -> Result<Value> {
        self.call(methods::SUBMIT_OHM_BLOCK, serde_json::json!([block]))
            .await
    }

    /// Returns an OHM-hosted OVM contract's code and storage.
    pub async fn get_ohm_contract(&self, ohm_id: &str, contract_id: &str) -> Result<Value> {
        self.call(
            methods::GET_OHM_CONTRACT,
            serde_json::json!([ohm_id, contract_id]),
        )
        .await
    }

    /// Simulates an OHM-hosted OVM contract call.
    pub async fn call_ohm_contract(
        &self,
        ohm_id: &str,
        contract_id: &str,
        entry_point: &str,
        arguments: &[u64],
        caller: &str,
        gas_limit: Option<u64>,
    ) -> Result<Value> {
        let mut payload = serde_json::json!({
            "ohmId": ohm_id,
            "contractId": contract_id,
            "entryPoint": entry_point,
            "arguments": arguments,
            "caller": caller,
        });
        if let Some(gas_limit) = gas_limit {
            payload["gasLimit"] = serde_json::json!(gas_limit);
        }
        self.call(methods::CALL_OHM_CONTRACT, payload).await
    }

    /// Returns vault status.
    pub async fn vault_status(&self) -> Result<Value> {
        self.call(methods::VAULT_STATUS, Value::Null).await
    }

    /// Creates a new vault.
    pub async fn vault_create(&self, password: &str) -> Result<Value> {
        self.call(methods::VAULT_CREATE, serde_json::json!([password]))
            .await
    }

    /// Imports a vault from a mnemonic.
    pub async fn vault_import(&self, mnemonic: &str, password: &str) -> Result<Value> {
        self.call(
            methods::VAULT_IMPORT,
            serde_json::json!([mnemonic, password]),
        )
        .await
    }

    /// Unlocks the vault.
    pub async fn vault_unlock(&self, password: &str) -> Result<Value> {
        self.call(methods::VAULT_UNLOCK, serde_json::json!([password]))
            .await
    }

    /// Locks the vault.
    pub async fn vault_lock(&self) -> Result<Value> {
        self.call(methods::VAULT_LOCK, Value::Null).await
    }

    /// Changes the vault password.
    pub async fn vault_change_password(&self, old: &str, new: &str) -> Result<Value> {
        self.call(
            methods::VAULT_CHANGE_PASSWORD,
            serde_json::json!([old, new]),
        )
        .await
    }

    /// Exports the vault mnemonic.
    pub async fn vault_export(&self, password: &str) -> Result<String> {
        self.call(methods::VAULT_EXPORT, serde_json::json!([password]))
            .await
            .map(|v| v.as_str().unwrap_or("").to_string())
    }
}

/// WebSocket client for walletd subscriptions.
pub struct WalletWsClient {
    stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
    next_id: u64,
}

impl WalletWsClient {
    /// Connects to the walletd WebSocket endpoint at `addr`.
    pub async fn connect(addr: SocketAddr) -> Result<Self> {
        let url = format!("ws://{addr}/ws");
        let (stream, _) = connect_async(&url)
            .await
            .context("websocket connect failed")?;
        Ok(Self { stream, next_id: 1 })
    }

    /// Subscribes to `topics` and returns the subscription ID.
    pub async fn subscribe(&mut self, topics: &[&str]) -> Result<String> {
        let id = self.next_id;
        self.next_id += 1;
        let req = RpcRequest::new(
            methods::SUBSCRIBE,
            serde_json::json!([topics]),
            serde_json::json!(id),
        );
        let text = serde_json::to_string(&req)?;
        self.stream
            .send(WsMessage::Text(text))
            .await
            .context("send failed")?;
        // Wait for the response
        while let Some(msg) = self.stream.next().await {
            let msg = msg.context("websocket error")?;
            if let WsMessage::Text(text) = msg {
                let resp: RpcResponse = serde_json::from_str(&text).context("invalid response")?;
                if let Some(err) = resp.error {
                    return Err(anyhow!("JSON-RPC error {}: {}", err.code, err.message));
                }
                if let Some(result) = resp.result {
                    if let Some(sub_id) = result.as_str() {
                        return Ok(sub_id.to_string());
                    }
                }
            }
        }
        Err(anyhow!("websocket closed"))
    }

    /// Unsubscribes from `subscription_id`.
    pub async fn unsubscribe(&mut self, subscription_id: &str) -> Result<()> {
        let id = self.next_id;
        self.next_id += 1;
        let req = RpcRequest::new(
            methods::UNSUBSCRIBE,
            serde_json::json!([subscription_id]),
            serde_json::json!(id),
        );
        let text = serde_json::to_string(&req)?;
        self.stream
            .send(WsMessage::Text(text))
            .await
            .context("send failed")?;
        Ok(())
    }

    /// Receives the next notification.
    pub async fn next_notification(&mut self) -> Result<WsNotice> {
        while let Some(msg) = self.stream.next().await {
            let msg = msg.context("websocket error")?;
            if let WsMessage::Text(text) = msg {
                let notice: WsNotice =
                    serde_json::from_str(&text).context("invalid notification")?;
                return Ok(notice);
            }
        }
        Err(anyhow!("websocket closed"))
    }

    /// Closes the WebSocket connection.
    pub async fn close(mut self) -> Result<()> {
        self.stream.close(None).await.context("close failed")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hex_works() {
        assert_eq!(parse_hex("0xdeadbeef"), Some(vec![0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(parse_hex("deadbeef"), Some(vec![0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(parse_hex("0x"), Some(vec![]));
        assert_eq!(parse_hex("0xgg"), None);
    }
}
