//! JSON-RPC method handlers for the walletd server.
//!
//! Each `ox_*` method is dispatched here, calling into the node client for chain data
//! or the vault for signing operations. See PLAN.md §12.

use crate::{node_client::NodeClient, AppState};
use oxydome_wallet_rpc::{
    balance_to_rpc, block_to_rpc, history_to_rpc, methods, status_to_rpc, to_hex, tx_to_rpc,
    utxo_to_rpc, value_index_to_rpc, RpcError, RpcRequest, RpcResponse,
};
use serde_json::{json, Value};
use std::str::FromStr;
use std::sync::Arc;

/// Dispatches a JSON-RPC request and returns the response.
pub async fn dispatch(state: &Arc<AppState>, req: &RpcRequest) -> RpcResponse {
    let id = req.id.clone();
    let params = req.params.clone();

    let result = match req.method.as_str() {
        methods::CHAIN_ID => handle_chain_id(state).await,
        methods::BLOCK_NUMBER => handle_block_number(state).await,
        methods::GET_BALANCE => handle_get_balance(state, &params).await,
        methods::GET_TRANSACTION_COUNT => handle_get_transaction_count().await,
        methods::GET_BLOCK_BY_NUMBER => handle_get_block_by_number(state, &params).await,
        methods::GET_BLOCK_BY_HASH => handle_get_block_by_hash(state, &params).await,
        methods::GET_TRANSACTION_BY_HASH => handle_get_transaction_by_hash(state, &params).await,
        methods::GET_TRANSACTION_RECEIPT => handle_get_transaction_receipt(state, &params).await,
        methods::GET_CODE => handle_get_code().await,
        methods::CALL => handle_call().await,
        methods::ESTIMATE_GAS => handle_estimate_gas().await,
        methods::GAS_PRICE => handle_gas_price().await,
        methods::FEE_HISTORY => handle_fee_history().await,
        methods::GET_LOGS => handle_get_logs().await,
        methods::SYNCING => handle_syncing().await,
        methods::ACCOUNTS => handle_accounts(state).await,
        methods::REQUEST_ACCOUNTS => handle_accounts(state).await,
        methods::SEND_TRANSACTION => handle_send_transaction(state, &params).await,
        methods::SIGN_MESSAGE => handle_sign_message(state, &params).await,
        methods::SIGN_TYPED_DATA => handle_sign_typed_data(state, &params).await,
        methods::VERIFY_MESSAGE => handle_verify_message(state, &params).await,
        methods::SUBSCRIBE => handle_subscribe(state, &params).await,
        methods::UNSUBSCRIBE => handle_unsubscribe(state, &params).await,
        methods::GET_UTXOS => handle_get_utxos(state, &params).await,
        methods::GET_HISTORY => handle_get_history(state, &params).await,
        methods::GET_PROOF => handle_get_proof(state, &params).await,
        methods::GET_VALUE_INDEX => handle_get_value_index(state).await,
        methods::VAULT_CREATE => handle_vault_create(state, &params).await,
        methods::VAULT_IMPORT => handle_vault_import(state, &params).await,
        methods::VAULT_UNLOCK => handle_vault_unlock(state, &params).await,
        methods::VAULT_LOCK => handle_vault_lock(state).await,
        methods::VAULT_STATUS => handle_vault_status(state).await,
        methods::VAULT_CHANGE_PASSWORD => handle_vault_change_password(state, &params).await,
        methods::VAULT_EXPORT => handle_vault_export(state, &params).await,
        _ => Err(RpcError::new(
            RpcError::METHOD_NOT_FOUND,
            format!("method not found: {}", req.method),
        )),
    };

    match result {
        Ok(value) => RpcResponse::success(id, value),
        Err(err) => RpcResponse::error(id, err),
    }
}

async fn handle_chain_id(state: &Arc<AppState>) -> Result<Value, RpcError> {
    Ok(json!(state.chain_id))
}

async fn handle_block_number(state: &Arc<AppState>) -> Result<Value, RpcError> {
    let mut client = NodeClient::connect(state.node_addr).await.map_err(|e| {
        RpcError::new(
            RpcError::INTERNAL_ERROR,
            format!("node connection failed: {e}"),
        )
    })?;
    let info = client
        .get_value_index()
        .await
        .map_err(|e| RpcError::new(RpcError::INTERNAL_ERROR, format!("node error: {e}")))?;
    Ok(json!(info.height))
}

async fn handle_get_balance(state: &Arc<AppState>, params: &Value) -> Result<Value, RpcError> {
    let address = params
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "expected address parameter"))?;
    let pubkey = parse_address(address)?;
    let mut client = NodeClient::connect(state.node_addr).await.map_err(|e| {
        RpcError::new(
            RpcError::INTERNAL_ERROR,
            format!("node connection failed: {e}"),
        )
    })?;
    let info = client
        .get_balance(pubkey)
        .await
        .map_err(|e| RpcError::new(RpcError::INTERNAL_ERROR, format!("node error: {e}")))?;
    Ok(serde_json::to_value(balance_to_rpc(&info)).unwrap())
}

async fn handle_get_transaction_count() -> Result<Value, RpcError> {
    Ok(json!(0))
}

async fn handle_get_block_by_number(
    state: &Arc<AppState>,
    params: &Value,
) -> Result<Value, RpcError> {
    let height = params
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.as_u64())
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "expected height parameter"))?;
    let mut client = NodeClient::connect(state.node_addr).await.map_err(|e| {
        RpcError::new(
            RpcError::INTERNAL_ERROR,
            format!("node connection failed: {e}"),
        )
    })?;
    let block = client
        .get_block_by_height(height)
        .await
        .map_err(|e| RpcError::new(RpcError::INTERNAL_ERROR, format!("node error: {e}")))?;
    match block {
        Some(b) => Ok(serde_json::to_value(block_to_rpc(&b)).unwrap()),
        None => Ok(Value::Null),
    }
}

async fn handle_get_block_by_hash(
    state: &Arc<AppState>,
    params: &Value,
) -> Result<Value, RpcError> {
    let hash_str = params
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "expected hash parameter"))?;
    let hash = parse_hash(hash_str)?;
    let mut client = NodeClient::connect(state.node_addr).await.map_err(|e| {
        RpcError::new(
            RpcError::INTERNAL_ERROR,
            format!("node connection failed: {e}"),
        )
    })?;
    // Fetch all blocks and find by hash (inefficient but simple)
    let value_index = client
        .get_value_index()
        .await
        .map_err(|e| RpcError::new(RpcError::INTERNAL_ERROR, format!("node error: {e}")))?;
    for h in 0..=value_index.height {
        if let Some(block) = client
            .get_block_by_height(h)
            .await
            .map_err(|e| RpcError::new(RpcError::INTERNAL_ERROR, format!("node error: {e}")))?
        {
            if block.hash() == hash {
                return Ok(serde_json::to_value(block_to_rpc(&block)).unwrap());
            }
        }
    }
    Ok(Value::Null)
}

async fn handle_get_transaction_by_hash(
    state: &Arc<AppState>,
    params: &Value,
) -> Result<Value, RpcError> {
    let txid_str = params
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "expected txid parameter"))?;
    let txid = parse_hash(txid_str)?;
    let mut client = NodeClient::connect(state.node_addr).await.map_err(|e| {
        RpcError::new(
            RpcError::INTERNAL_ERROR,
            format!("node connection failed: {e}"),
        )
    })?;
    let (tx, location, _status) = client
        .get_transaction(txid)
        .await
        .map_err(|e| RpcError::new(RpcError::INTERNAL_ERROR, format!("node error: {e}")))?;
    match tx {
        Some(t) => {
            let loc = location
                .as_ref()
                .map(|l| (l.height, &l.block_hash, l.position));
            Ok(serde_json::to_value(tx_to_rpc(&t, loc)).unwrap())
        }
        None => Ok(Value::Null),
    }
}

async fn handle_get_transaction_receipt(
    state: &Arc<AppState>,
    params: &Value,
) -> Result<Value, RpcError> {
    let txid_str = params
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "expected txid parameter"))?;
    let txid = parse_hash(txid_str)?;
    let mut client = NodeClient::connect(state.node_addr).await.map_err(|e| {
        RpcError::new(
            RpcError::INTERNAL_ERROR,
            format!("node connection failed: {e}"),
        )
    })?;
    let (tx, location, status) = client
        .get_transaction(txid)
        .await
        .map_err(|e| RpcError::new(RpcError::INTERNAL_ERROR, format!("node error: {e}")))?;
    let mut receipt = status_to_rpc(&status);
    if let Some(t) = tx {
        receipt.txid = to_hex(t.txid().as_bytes());
    }
    if let Some(loc) = location {
        receipt.block_hash = Some(to_hex(loc.block_hash.as_bytes()));
        receipt.position = Some(loc.position);
    }
    Ok(serde_json::to_value(receipt).unwrap())
}

async fn handle_get_code() -> Result<Value, RpcError> {
    Ok(json!("0x"))
}

async fn handle_call() -> Result<Value, RpcError> {
    Err(RpcError::new(
        RpcError::METHOD_NOT_SUPPORTED,
        "eth_call is not supported on Oxydome",
    ))
}

async fn handle_estimate_gas() -> Result<Value, RpcError> {
    Err(RpcError::new(
        RpcError::METHOD_NOT_SUPPORTED,
        "eth_estimateGas is not supported on Oxydome",
    ))
}

async fn handle_gas_price() -> Result<Value, RpcError> {
    Ok(json!("1"))
}

async fn handle_fee_history() -> Result<Value, RpcError> {
    Ok(json!([]))
}

async fn handle_get_logs() -> Result<Value, RpcError> {
    Ok(json!([]))
}

async fn handle_syncing() -> Result<Value, RpcError> {
    Ok(json!(false))
}

async fn handle_accounts(state: &Arc<AppState>) -> Result<Value, RpcError> {
    let vault = state.vault.lock().await;
    let accounts: Vec<String> = vault
        .accounts()
        .iter()
        .map(|pk| to_hex(pk.as_bytes()))
        .collect();
    Ok(json!(accounts))
}

async fn handle_send_transaction(state: &Arc<AppState>, params: &Value) -> Result<Value, RpcError> {
    // Parse the transaction from params
    let tx_value = params
        .as_array()
        .and_then(|a| a.first())
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "expected transaction parameter"))?;
    let tx = parse_rpc_transaction(tx_value)?;

    let mut client = NodeClient::connect(state.node_addr).await.map_err(|e| {
        RpcError::new(
            RpcError::INTERNAL_ERROR,
            format!("node connection failed: {e}"),
        )
    })?;
    let (txid, accepted, error) = client
        .submit_transaction(tx)
        .await
        .map_err(|e| RpcError::new(RpcError::INTERNAL_ERROR, format!("node error: {e}")))?;
    if accepted {
        Ok(json!(to_hex(txid.as_bytes())))
    } else {
        Err(RpcError::new(
            RpcError::TX_REJECTED,
            error.unwrap_or_else(|| "transaction rejected".into()),
        ))
    }
}

async fn handle_sign_message(state: &Arc<AppState>, params: &Value) -> Result<Value, RpcError> {
    let message = params
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "expected message parameter"))?;
    let vault = state.vault.lock().await;
    if !vault.is_unlocked() {
        return Err(RpcError::new(RpcError::VAULT_LOCKED, "vault is locked"));
    }
    let hash = oxydome_wallet::sign::message_hash(
        &oxydome_wallet::sign::DomainLabel::Personal,
        message.as_bytes(),
    );
    let sig = vault
        .sign_hash(0, 0, &hash.0)
        .map_err(|e| RpcError::new(RpcError::INTERNAL_ERROR, format!("{e}")))?;
    Ok(json!(to_hex(&sig)))
}

async fn handle_sign_typed_data(state: &Arc<AppState>, params: &Value) -> Result<Value, RpcError> {
    let data = params
        .as_array()
        .and_then(|a| a.first())
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "expected typed data parameter"))?;
    let vault = state.vault.lock().await;
    if !vault.is_unlocked() {
        return Err(RpcError::new(RpcError::VAULT_LOCKED, "vault is locked"));
    }
    let canonical = oxydome_wallet::sign::canonical_json(data)
        .map_err(|e| RpcError::new(RpcError::INVALID_PARAMS, format!("{e}")))?;
    let hash = oxydome_wallet::sign::message_hash(
        &oxydome_wallet::sign::DomainLabel::TypedData,
        &canonical,
    );
    let sig = vault
        .sign_hash(0, 0, &hash.0)
        .map_err(|e| RpcError::new(RpcError::INTERNAL_ERROR, format!("{e}")))?;
    Ok(json!(to_hex(&sig)))
}

async fn handle_verify_message(state: &Arc<AppState>, params: &Value) -> Result<Value, RpcError> {
    let args = params
        .as_array()
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "expected parameters"))?;
    let message = args
        .first()
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "expected message"))?;
    let signature = args
        .get(1)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "expected signature"))?;
    let address = args
        .get(2)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "expected address"))?;
    let pubkey = parse_address(address)?;
    let sig_bytes = parse_hex(signature)
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "invalid signature hex"))?;
    if sig_bytes.len() != 64 {
        return Err(RpcError::new(
            RpcError::INVALID_PARAMS,
            "signature must be 64 bytes",
        ));
    }
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&sig_bytes);

    // Compute the personal message hash
    let message_hash = oxydome_wallet::sign::message_hash(
        &oxydome_wallet::sign::DomainLabel::Personal,
        message.as_bytes(),
    );
    let verified = oxydome_crypto::verify(&pubkey, &message_hash.0, &oxydome_crypto::Sig(sig));
    let _ = state; // suppress unused warning
    Ok(json!(verified))
}

async fn handle_subscribe(state: &Arc<AppState>, params: &Value) -> Result<Value, RpcError> {
    let topics = params
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.as_array())
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "expected topics array"))?;
    let topic_names: Vec<String> = topics
        .iter()
        .filter_map(|t| t.as_str().map(|s| s.to_string()))
        .collect();
    let sub_id = format!("0x{:x}", state.next_sub_id());
    // Spawn background task to forward node events
    let hub = state.hub.clone();
    let sub_id_clone = sub_id.clone();
    let topics_clone = topic_names.clone();
    tokio::spawn(async move {
        let mut rx = hub.subscribe();
        while let Ok(notice) = rx.recv().await {
            // Filter by topics
            let should_forward = topics_clone.is_empty()
                || topics_clone.iter().any(|t| match t.as_str() {
                    "newBlocks" => {
                        notice.method == "ox_subscription"
                            && notice.params.result.get("block_hash").is_some()
                    }
                    "txAccepted" => {
                        notice.method == "ox_subscription"
                            && notice.params.result.get("event").and_then(|e| e.as_str())
                                == Some("accepted")
                    }
                    "txConfirmed" => {
                        notice.method == "ox_subscription"
                            && notice.params.result.get("event").and_then(|e| e.as_str())
                                == Some("confirmed")
                    }
                    "txFailed" => {
                        notice.method == "ox_subscription"
                            && notice.params.result.get("event").and_then(|e| e.as_str())
                                == Some("rejected")
                    }
                    "mempool" => {
                        notice.method == "ox_subscription"
                            && notice.params.result.get("event").and_then(|e| e.as_str())
                                == Some("mempool")
                    }
                    "balanceChanged" => {
                        notice.method == "ox_subscription"
                            && notice.params.result.get("event").and_then(|e| e.as_str())
                                == Some("balance")
                    }
                    _ => false,
                });
            if should_forward {
                // Forward to the WebSocket client
                let _ = (notice, sub_id_clone.clone());
            }
        }
    });
    Ok(json!(sub_id))
}

async fn handle_unsubscribe(state: &Arc<AppState>, params: &Value) -> Result<Value, RpcError> {
    let sub_id = params
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "expected subscription id"))?;
    let _ = sub_id;
    let _ = state;
    Ok(json!(true))
}

async fn handle_get_utxos(state: &Arc<AppState>, params: &Value) -> Result<Value, RpcError> {
    let address = params
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "expected address parameter"))?;
    let pubkey = parse_address(address)?;
    let mut client = NodeClient::connect(state.node_addr).await.map_err(|e| {
        RpcError::new(
            RpcError::INTERNAL_ERROR,
            format!("node connection failed: {e}"),
        )
    })?;
    let utxos = client
        .get_utxos(pubkey)
        .await
        .map_err(|e| RpcError::new(RpcError::INTERNAL_ERROR, format!("node error: {e}")))?;
    let rpc_utxos: Vec<_> = utxos.iter().map(utxo_to_rpc).collect();
    Ok(serde_json::to_value(rpc_utxos).unwrap())
}

async fn handle_get_history(state: &Arc<AppState>, params: &Value) -> Result<Value, RpcError> {
    let args = params
        .as_array()
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "expected parameters"))?;
    let address = args
        .first()
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "expected address"))?;
    let cursor = args.get(1).and_then(|v| v.as_u64()).unwrap_or(0);
    let limit = args.get(2).and_then(|v| v.as_u64()).unwrap_or(50) as u32;
    let pubkey = parse_address(address)?;
    let mut client = NodeClient::connect(state.node_addr).await.map_err(|e| {
        RpcError::new(
            RpcError::INTERNAL_ERROR,
            format!("node connection failed: {e}"),
        )
    })?;
    let (entries, next_cursor) = client
        .get_history(pubkey, cursor, limit)
        .await
        .map_err(|e| RpcError::new(RpcError::INTERNAL_ERROR, format!("node error: {e}")))?;
    let rpc_entries: Vec<_> = entries.iter().map(history_to_rpc).collect();
    Ok(json!({
        "entries": rpc_entries,
        "nextCursor": next_cursor,
    }))
}

async fn handle_get_proof(state: &Arc<AppState>, params: &Value) -> Result<Value, RpcError> {
    let args = params
        .as_array()
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "expected parameters"))?;
    let txid_str = args
        .first()
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "expected txid"))?;
    let index = args.get(1).and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let txid = parse_hash(txid_str)?;
    let outpoint = oxydome_core::OutPoint::new(txid, index);
    let mut client = NodeClient::connect(state.node_addr).await.map_err(|e| {
        RpcError::new(
            RpcError::INTERNAL_ERROR,
            format!("node connection failed: {e}"),
        )
    })?;
    let (entry, proof) = client
        .get_utxo_proof(outpoint)
        .await
        .map_err(|e| RpcError::new(RpcError::INTERNAL_ERROR, format!("node error: {e}")))?;
    Ok(json!({
        "entry": entry.map(|e| {
            json!({
                "txid": to_hex(e.outpoint.txid.as_bytes()),
                "index": e.outpoint.index,
                "amount": e.output.amount.to_string(),
                "recipient": to_hex(e.output.recipient.as_bytes()),
                "createdHeight": e.created_height,
            })
        }),
        "proof": proof.map(|p| {
            json!({
                "siblings": p.siblings.iter().map(|s| to_hex(s.as_bytes())).collect::<Vec<_>>(),
            })
        }),
    }))
}

async fn handle_get_value_index(state: &Arc<AppState>) -> Result<Value, RpcError> {
    let mut client = NodeClient::connect(state.node_addr).await.map_err(|e| {
        RpcError::new(
            RpcError::INTERNAL_ERROR,
            format!("node connection failed: {e}"),
        )
    })?;
    let info = client
        .get_value_index()
        .await
        .map_err(|e| RpcError::new(RpcError::INTERNAL_ERROR, format!("node error: {e}")))?;
    Ok(serde_json::to_value(value_index_to_rpc(&info)).unwrap())
}

async fn handle_vault_create(state: &Arc<AppState>, params: &Value) -> Result<Value, RpcError> {
    let password = params
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "expected password"))?;
    let mut vault = state.vault.lock().await;
    match vault.create(password) {
        Ok(mnemonic) => Ok(json!({ "mnemonic": mnemonic })),
        Err(e) => Err(RpcError::new(RpcError::INTERNAL_ERROR, format!("{e}"))),
    }
}

async fn handle_vault_import(state: &Arc<AppState>, params: &Value) -> Result<Value, RpcError> {
    let args = params
        .as_array()
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "expected parameters"))?;
    let mnemonic = args
        .first()
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "expected mnemonic"))?;
    let password = args
        .get(1)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "expected password"))?;
    let mut vault = state.vault.lock().await;
    match vault.import(mnemonic, password) {
        Ok(()) => Ok(json!({ "success": true })),
        Err(e) => Err(RpcError::new(RpcError::INTERNAL_ERROR, format!("{e}"))),
    }
}

async fn handle_vault_unlock(state: &Arc<AppState>, params: &Value) -> Result<Value, RpcError> {
    let password = params
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "expected password"))?;
    let mut vault = state.vault.lock().await;
    match vault.unlock(password) {
        Ok(()) => Ok(json!({ "success": true })),
        Err(e) => Err(RpcError::new(RpcError::INTERNAL_ERROR, format!("{e}"))),
    }
}

async fn handle_vault_lock(state: &Arc<AppState>) -> Result<Value, RpcError> {
    let mut vault = state.vault.lock().await;
    vault.lock();
    Ok(json!({ "success": true }))
}

async fn handle_vault_status(state: &Arc<AppState>) -> Result<Value, RpcError> {
    let vault = state.vault.lock().await;
    Ok(json!({
        "locked": !vault.is_unlocked(),
        "accountCount": vault.account_count(),
    }))
}

async fn handle_vault_change_password(
    state: &Arc<AppState>,
    params: &Value,
) -> Result<Value, RpcError> {
    let args = params
        .as_array()
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "expected parameters"))?;
    let old = args
        .first()
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "expected old password"))?;
    let new = args
        .get(1)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "expected new password"))?;
    let mut vault = state.vault.lock().await;
    match vault.change_password(old, new) {
        Ok(()) => Ok(json!({ "success": true })),
        Err(e) => Err(RpcError::new(RpcError::INTERNAL_ERROR, format!("{e}"))),
    }
}

async fn handle_vault_export(state: &Arc<AppState>, params: &Value) -> Result<Value, RpcError> {
    let _password = params
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "expected password"))?;
    let vault = state.vault.lock().await;
    match vault.export() {
        Ok(mnemonic) => Ok(json!({ "mnemonic": mnemonic })),
        Err(e) => Err(RpcError::new(RpcError::INTERNAL_ERROR, format!("{e}"))),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_address(s: &str) -> Result<oxydome_core::PublicKey, RpcError> {
    // Try hex first
    if let Some(bytes) = parse_hex(s) {
        if bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            return Ok(oxydome_core::PublicKey::from_bytes(arr));
        }
    }
    // Try bech32m
    oxydome_wallet::address::Address::from_str(s)
        .map(|a| a.public_key())
        .map_err(|_| RpcError::new(RpcError::INVALID_ADDRESS, format!("invalid address: {s}")))
}

fn parse_hash(s: &str) -> Result<oxydome_core::Hash, RpcError> {
    let bytes = parse_hex(s)
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, format!("invalid hash: {s}")))?;
    if bytes.len() != 64 {
        return Err(RpcError::new(
            RpcError::INVALID_PARAMS,
            format!("hash must be 64 bytes: {s}"),
        ));
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&bytes);
    Ok(oxydome_core::Hash::from_bytes(arr))
}

fn parse_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn parse_rpc_transaction(value: &Value) -> Result<oxydome_core::Transaction, RpcError> {
    let obj = value
        .as_object()
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "expected transaction object"))?;
    let inputs_val = obj
        .get("inputs")
        .and_then(|v| v.as_array())
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "missing inputs"))?;
    let outputs_val = obj
        .get("outputs")
        .and_then(|v| v.as_array())
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "missing outputs"))?;
    let fee_str = obj
        .get("fee")
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "missing fee"))?;
    let fee = fee_str
        .parse::<u128>()
        .map_err(|_| RpcError::new(RpcError::INVALID_PARAMS, "invalid fee"))?;

    let mut inputs = Vec::new();
    for inp in inputs_val {
        let txid_str = inp
            .get("txid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "missing input txid"))?;
        let index = inp
            .get("index")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "missing input index"))?;
        let owner_str = inp
            .get("owner")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "missing input owner"))?;
        let sig_str = inp
            .get("signature")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "missing input signature"))?;
        let txid = parse_hash(txid_str)?;
        let owner = parse_address(owner_str)?;
        let sig_bytes = parse_hex(sig_str)
            .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "invalid signature hex"))?;
        if sig_bytes.len() != 64 {
            return Err(RpcError::new(
                RpcError::INVALID_PARAMS,
                "signature must be 64 bytes",
            ));
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&sig_bytes);
        inputs.push(oxydome_core::TxInput {
            prev_out: oxydome_core::OutPoint::new(txid, index as u32),
            owner,
            signature: oxydome_crypto::Sig(sig),
        });
    }

    let mut outputs = Vec::new();
    for out in outputs_val {
        let amount_str = out
            .get("amount")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "missing output amount"))?;
        let amount = amount_str
            .parse::<u128>()
            .map_err(|_| RpcError::new(RpcError::INVALID_PARAMS, "invalid amount"))?;
        let recipient_str = out
            .get("recipient")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "missing output recipient"))?;
        let recipient = parse_address(recipient_str)?;
        outputs.push(oxydome_core::TxOutput::spendable(amount, recipient));
    }

    Ok(oxydome_core::Transaction {
        inputs,
        outputs,
        fee,
    })
}
