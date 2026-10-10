//! JSON-RPC method handlers for the walletd server.
//!
//! Each `ox_*` method is dispatched here, calling into the node client for chain data
//! or the vault for signing operations. See PLAN.md §12.

use crate::{node_client::NodeClient, AppState};
use oxydome_wallet_rpc::{
    balance_to_rpc, block_to_rpc, history_to_rpc, methods, ohm_block_to_rpc,
    ohm_contract_call_to_rpc, ohm_contract_to_rpc, ohm_to_rpc, status_to_rpc, to_hex, tx_to_rpc,
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
        methods::GET_CODE => handle_get_code(state, &params).await,
        methods::GET_ASSET_MANIFEST => handle_get_asset_manifest(state, &params).await,
        methods::GET_ASSET => handle_get_asset(state, &params).await,
        methods::PUT_CONTENT => handle_put_content(state, &params).await,
        methods::CALL => handle_call(state, &params).await,
        methods::ESTIMATE_GAS => handle_estimate_gas(state, &params).await,
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
        methods::GET_DAO => handle_get_dao(state, &params).await,
        methods::SUBMIT_DAO_OPERATION => handle_submit_dao_operation(state, &params).await,
        methods::GET_OHM => handle_get_ohm(state, &params).await,
        methods::GET_OHM_BLOCK => handle_get_ohm_block(state, &params).await,
        methods::GET_OHM_BALANCE => handle_get_ohm_balance(state, &params).await,
        methods::SUBMIT_OHM_OPERATION => handle_submit_ohm_operation(state, &params).await,
        methods::SUBMIT_OHM_BLOCK => handle_submit_ohm_block(state, &params).await,
        methods::GET_OHM_CONTRACT => handle_get_ohm_contract(state, &params).await,
        methods::CALL_OHM_CONTRACT => handle_call_ohm_contract(state, &params).await,
        methods::GET_GAS_BALANCE => handle_get_gas_balance(state, &params).await,
        methods::GET_GAS_SUPPLY => handle_get_gas_supply(state, &params).await,
        methods::GET_GAS_PRICE => handle_get_gas_price(state, &params).await,
        methods::GET_GAS_AIRDROP_INFO => handle_airdrop_info(state, &params).await,
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
    if let Some(t) = &tx {
        receipt.txid = to_hex(t.txid().as_bytes());
    }
    if let Some(loc) = location {
        receipt.block_hash = Some(to_hex(loc.block_hash.as_bytes()));
        receipt.position = Some(loc.position);
        if tx
            .as_ref()
            .is_some_and(|transaction| transaction.ovm_action.is_some())
        {
            if let Some(block) = client
                .get_block_by_height(loc.height)
                .await
                .map_err(|error| RpcError::new(RpcError::INTERNAL_ERROR, error.to_string()))?
            {
                receipt.ovm_receipt = block
                    .ovm_receipts
                    .into_iter()
                    .find(|ovm_receipt| ovm_receipt.txid == txid);
                if let (Some(transaction), Some(action), Some(ovm_receipt), Some(input)) = (
                    tx.as_ref(),
                    tx.as_ref()
                        .and_then(|transaction| transaction.ovm_action.as_ref()),
                    receipt.ovm_receipt.as_ref(),
                    tx.as_ref()
                        .and_then(|transaction| transaction.inputs.first()),
                ) {
                    let refund = action.gas_limit().saturating_sub(ovm_receipt.gas_used);
                    receipt.ovm_actual_fee = Some(
                        transaction
                            .fee
                            .saturating_sub(u128::from(refund))
                            .to_string(),
                    );
                    if refund > 0 {
                        receipt.ovm_gas_refund = Some(oxydome_wallet_rpc::RpcOutput {
                            amount: refund.to_string(),
                            recipient: to_hex(input.owner.as_bytes()),
                            kind: "spendable".into(),
                            created_height: loc.height,
                            mature: true,
                        });
                    }
                }
            }
        }
    }
    Ok(serde_json::to_value(receipt).unwrap())
}

async fn handle_get_code(state: &Arc<AppState>, params: &Value) -> Result<Value, RpcError> {
    let contract_id = params
        .as_array()
        .and_then(|values| values.first())
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "expected contract id"))?;
    let mut client = NodeClient::connect(state.node_addr)
        .await
        .map_err(|error| {
            RpcError::new(
                RpcError::INTERNAL_ERROR,
                format!("node connection failed: {error}"),
            )
        })?;
    match client
        .get_ovm_code(parse_hash(contract_id)?)
        .await
        .map_err(|error| RpcError::new(RpcError::INTERNAL_ERROR, error.to_string()))?
    {
        Some(code) => Ok(json!(to_hex(&code))),
        None => Err(RpcError::new(
            RpcError::RESOURCE_NOT_FOUND,
            "OVM contract was not found",
        )),
    }
}

async fn handle_get_asset_manifest(
    state: &Arc<AppState>,
    params: &Value,
) -> Result<Value, RpcError> {
    let contract_id = params
        .as_array()
        .and_then(|values| values.first())
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "expected contract id"))?;
    let mut client = NodeClient::connect(state.node_addr)
        .await
        .map_err(|error| node_connection_error(error.to_string()))?;
    let artifact = get_contract_artifact(&mut client, parse_hash(contract_id)?).await?;
    let manifest_hash = artifact.asset_manifest_hash.ok_or_else(|| {
        RpcError::new(
            RpcError::RESOURCE_NOT_FOUND,
            "contract has no optional asset manifest",
        )
    })?;
    let manifest = fetch_asset_manifest(&mut client, manifest_hash).await?;
    Ok(json!({
        "manifestHash": to_hex(manifest_hash.as_bytes()),
        "entries": manifest.entries.iter().map(|entry| json!({
            "path": entry.path,
            "contentHash": to_hex(entry.content_hash.as_bytes()),
            "size": entry.size.to_string(),
        })).collect::<Vec<_>>(),
    }))
}

async fn handle_get_asset(state: &Arc<AppState>, params: &Value) -> Result<Value, RpcError> {
    let object = params
        .as_object()
        .or_else(|| {
            params
                .as_array()
                .and_then(|values| values.first())
                .and_then(Value::as_object)
        })
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "expected contractId and path"))?;
    let contract_id = object
        .get("contractId")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "missing contractId"))?;
    let path = object
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "missing asset path"))?;
    let mut client = NodeClient::connect(state.node_addr)
        .await
        .map_err(|error| node_connection_error(error.to_string()))?;
    let artifact = get_contract_artifact(&mut client, parse_hash(contract_id)?).await?;
    let manifest_hash = artifact.asset_manifest_hash.ok_or_else(|| {
        RpcError::new(
            RpcError::RESOURCE_NOT_FOUND,
            "contract has no optional asset manifest",
        )
    })?;
    let manifest = fetch_asset_manifest(&mut client, manifest_hash).await?;
    let entry = manifest.asset(path).ok_or_else(|| {
        RpcError::new(
            RpcError::RESOURCE_NOT_FOUND,
            "asset path is not in the manifest",
        )
    })?;
    let entry = entry.clone();
    let content = fetch_content(&mut client, entry.content_hash).await?;
    if content.len() as u64 != entry.size {
        return Err(RpcError::new(
            RpcError::INTERNAL_ERROR,
            "stored asset size does not match its manifest",
        ));
    }
    Ok(json!({
        "path": entry.path,
        "contentHash": to_hex(entry.content_hash.as_bytes()),
        "size": entry.size.to_string(),
        "content": to_hex(&content),
    }))
}

async fn handle_put_content(state: &Arc<AppState>, params: &Value) -> Result<Value, RpcError> {
    let encoded = params
        .as_object()
        .and_then(|object| object.get("content"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            RpcError::new(
                RpcError::INVALID_PARAMS,
                "expected an object with hex-encoded content",
            )
        })?;
    let content = parse_hex(encoded)
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "invalid content hex"))?;
    if content.len() as u64 > oxydome_ovm::MAX_ASSET_BYTES {
        return Err(RpcError::new(
            RpcError::INVALID_PARAMS,
            "content exceeds the per-item asset size limit",
        ));
    }
    let mut client = NodeClient::connect(state.node_addr)
        .await
        .map_err(|error| node_connection_error(error.to_string()))?;
    let hash = client
        .store_content(content)
        .await
        .map_err(|error| RpcError::new(RpcError::TX_REJECTED, error))?;
    Ok(json!(to_hex(hash.as_bytes())))
}

async fn get_contract_artifact(
    client: &mut NodeClient,
    contract_id: oxydome_core::Hash,
) -> Result<oxydome_ovm::ContractArtifact, RpcError> {
    let code = client
        .get_ovm_code(contract_id)
        .await
        .map_err(|error| node_connection_error(error.to_string()))?
        .ok_or_else(|| RpcError::new(RpcError::RESOURCE_NOT_FOUND, "OVM contract was not found"))?;
    oxydome_ovm::ContractArtifact::decode(&code)
        .map_err(|error| RpcError::new(RpcError::INTERNAL_ERROR, error.to_string()))
}

async fn fetch_asset_manifest(
    client: &mut NodeClient,
    manifest_hash: oxydome_core::Hash,
) -> Result<oxydome_ovm::AssetManifest, RpcError> {
    let bytes = fetch_content(client, manifest_hash).await?;
    oxydome_ovm::AssetManifest::decode(&bytes)
        .map_err(|error| RpcError::new(RpcError::INTERNAL_ERROR, error.to_string()))
}

async fn fetch_content(
    client: &mut NodeClient,
    hash: oxydome_core::Hash,
) -> Result<Vec<u8>, RpcError> {
    let content = client
        .get_content(hash)
        .await
        .map_err(|error| node_connection_error(error.to_string()))?
        .ok_or_else(|| {
            RpcError::new(
                RpcError::RESOURCE_NOT_FOUND,
                format!("content {} is not available from this node", hash),
            )
        })?;
    if oxydome_ovm::content_hash(&content) != hash {
        return Err(RpcError::new(
            RpcError::INTERNAL_ERROR,
            "node returned content that does not match its requested hash",
        ));
    }
    Ok(content)
}

fn node_connection_error(error: String) -> RpcError {
    RpcError::new(
        RpcError::INTERNAL_ERROR,
        format!("node connection failed: {error}"),
    )
}

async fn handle_call(state: &Arc<AppState>, params: &Value) -> Result<Value, RpcError> {
    if has_named_entry_point(params) {
        let (contract_id, entry_point, arguments, caller, gas_limit) =
            parse_ovm_contract_call(params)?;
        let mut client = NodeClient::connect(state.node_addr)
            .await
            .map_err(|error| {
                RpcError::new(
                    RpcError::INTERNAL_ERROR,
                    format!("node connection failed: {error}"),
                )
            })?;
        let execution = client
            .call_ovm_contract(contract_id, entry_point, arguments, caller, gas_limit)
            .await
            .map_err(|error| RpcError::new(RpcError::TX_REJECTED, error))?;
        return Ok(ovm_execution_to_rpc(&execution));
    }
    let (contract_id, arguments, gas_limit) = parse_ovm_call(params)?;
    let mut client = NodeClient::connect(state.node_addr)
        .await
        .map_err(|error| {
            RpcError::new(
                RpcError::INTERNAL_ERROR,
                format!("node connection failed: {error}"),
            )
        })?;
    let execution = client
        .call_ovm(contract_id, arguments, gas_limit)
        .await
        .map_err(|error| RpcError::new(RpcError::TX_REJECTED, error))?;
    Ok(ovm_execution_to_rpc(&execution))
}

fn ovm_execution_to_rpc(execution: &oxydome_ovm::Execution) -> Value {
    json!({
        "returnData": to_hex(&execution.return_value.map(u64::to_le_bytes).map_or_else(Vec::new, |value| value.to_vec())),
        "gasUsed": execution.gas_used.to_string(),
        "logs": execution.logs.iter().map(|log| json!({
            "topic": log.topic,
            "value": log.value.to_string(),
        })).collect::<Vec<_>>(),
    })
}

async fn handle_estimate_gas(state: &Arc<AppState>, params: &Value) -> Result<Value, RpcError> {
    if has_named_entry_point(params) {
        let (contract_id, entry_point, arguments, caller, _) = parse_ovm_contract_call(params)?;
        let mut client = NodeClient::connect(state.node_addr)
            .await
            .map_err(|error| {
                RpcError::new(
                    RpcError::INTERNAL_ERROR,
                    format!("node connection failed: {error}"),
                )
            })?;
        let execution = client
            .call_ovm_contract(
                contract_id,
                entry_point,
                arguments,
                caller,
                oxydome_core::tx::MAX_OVM_GAS_LIMIT,
            )
            .await
            .map_err(|error| RpcError::new(RpcError::TX_REJECTED, error))?;
        return Ok(json!(execution.gas_used.to_string()));
    }
    let (contract_id, arguments, _) = parse_ovm_call(params)?;
    let mut client = NodeClient::connect(state.node_addr)
        .await
        .map_err(|error| {
            RpcError::new(
                RpcError::INTERNAL_ERROR,
                format!("node connection failed: {error}"),
            )
        })?;
    let execution = client
        .call_ovm(contract_id, arguments, oxydome_core::tx::MAX_OVM_GAS_LIMIT)
        .await
        .map_err(|error| RpcError::new(RpcError::TX_REJECTED, error))?;
    Ok(json!(execution.gas_used.to_string()))
}

fn has_named_entry_point(params: &Value) -> bool {
    params
        .as_object()
        .or_else(|| {
            params
                .as_array()
                .and_then(|items| items.first())
                .and_then(Value::as_object)
        })
        .is_some_and(|object| object.contains_key("entryPoint"))
}

fn parse_ovm_contract_call(
    params: &Value,
) -> Result<
    (
        oxydome_core::Hash,
        String,
        Vec<u64>,
        oxydome_core::PublicKey,
        u64,
    ),
    RpcError,
> {
    let object = params
        .as_object()
        .or_else(|| {
            params
                .as_array()
                .and_then(|items| items.first())
                .and_then(Value::as_object)
        })
        .ok_or_else(|| {
            RpcError::new(
                RpcError::INVALID_PARAMS,
                "expected call object with contractId and entryPoint",
            )
        })?;
    let contract_id = object
        .get("contractId")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "missing contractId"))?;
    let entry_point = object
        .get("entryPoint")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "missing entryPoint"))?
        .to_owned();
    let arguments = object
        .get("arguments")
        .and_then(Value::as_array)
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "missing arguments"))?
        .iter()
        .map(|value| {
            value.as_u64().ok_or_else(|| {
                RpcError::new(
                    RpcError::INVALID_PARAMS,
                    "OVM arguments must be unsigned integers",
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if arguments.len() + oxydome_ovm::AUTHORITY_WORD_COUNT > oxydome_ovm::MAX_ARGUMENTS {
        return Err(RpcError::new(
            RpcError::INVALID_PARAMS,
            "OVM contract call exceeds the argument limit",
        ));
    }
    let caller = match object.get("from") {
        Some(Value::String(address)) => parse_address(address)?,
        Some(_) => {
            return Err(RpcError::new(
                RpcError::INVALID_PARAMS,
                "from must be an Oxydome address",
            ))
        }
        None => oxydome_core::PublicKey::from_bytes([0; 32]),
    };
    let gas_limit = object
        .get("gasLimit")
        .and_then(Value::as_u64)
        .unwrap_or(oxydome_core::tx::MAX_OVM_GAS_LIMIT);
    if gas_limit < oxydome_ovm::ACTION_INTRINSIC_GAS + oxydome_ovm::CONTRACT_DISPATCH_GAS
        || gas_limit > oxydome_core::tx::MAX_OVM_GAS_LIMIT
    {
        return Err(RpcError::new(
            RpcError::INVALID_PARAMS,
            "invalid OVM contract gasLimit",
        ));
    }
    Ok((
        parse_hash(contract_id)?,
        entry_point,
        arguments,
        caller,
        gas_limit,
    ))
}

fn parse_ovm_call(params: &Value) -> Result<(oxydome_core::Hash, Vec<u64>, u64), RpcError> {
    let object = params
        .as_object()
        .or_else(|| {
            params
                .as_array()
                .and_then(|items| items.first())
                .and_then(Value::as_object)
        })
        .ok_or_else(|| {
            RpcError::new(
                RpcError::INVALID_PARAMS,
                "expected call object with contractId and arguments",
            )
        })?;
    let contract_id = object
        .get("contractId")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "missing contractId"))?;
    let arguments = object
        .get("arguments")
        .and_then(Value::as_array)
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "missing arguments"))?
        .iter()
        .map(|value| {
            value.as_u64().ok_or_else(|| {
                RpcError::new(
                    RpcError::INVALID_PARAMS,
                    "OVM arguments must be unsigned integers",
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if arguments.len() > oxydome_core::MAX_OVM_ARGUMENTS {
        return Err(RpcError::new(
            RpcError::INVALID_PARAMS,
            "OVM call exceeds the 64-argument limit",
        ));
    }
    let gas_limit = object
        .get("gasLimit")
        .and_then(Value::as_u64)
        .unwrap_or(oxydome_core::tx::MAX_OVM_GAS_LIMIT);
    if gas_limit == 0 || gas_limit > oxydome_core::tx::MAX_OVM_GAS_LIMIT {
        return Err(RpcError::new(
            RpcError::INVALID_PARAMS,
            "invalid OVM gasLimit",
        ));
    }
    Ok((parse_hash(contract_id)?, arguments, gas_limit))
}

async fn handle_gas_price() -> Result<Value, RpcError> {
    Ok(json!("1"))
}

async fn handle_fee_history() -> Result<Value, RpcError> {
    Ok(json!([]))
}

async fn handle_get_gas_balance(state: &Arc<AppState>, params: &Value) -> Result<Value, RpcError> {
    // GAS balance query - connects to node via NodeClient
    // TODO: Implement NodeClient method call when available
    let _owner = params
        .as_array()
        .and_then(|values| values.first())
        .and_then(|v| v.as_str());
    Ok(json!({ "balance": "0", "owner": "pending" }))
}

async fn handle_get_gas_supply(state: &Arc<AppState>, params: &Value) -> Result<Value, RpcError> {
    // GAS supply query - connects to node via NodeClient
    // TODO: Implement NodeClient method call when available
    Ok(json!({ "supply": "0" }))
}

async fn handle_get_gas_price(state: &Arc<AppState>, params: &Value) -> Result<Value, RpcError> {
    // GAS price query - connects to node via NodeClient
    // TODO: Implement NodeClient method call when available
    Ok(json!({ "price": "0" }))
}

async fn handle_airdrop_info(state: &Arc<AppState>, params: &Value) -> Result<Value, RpcError> {
    // GAS airdrop info query - connects to node via NodeClient
    // TODO: Implement NodeClient method call when available
    Ok(json!({ "height": 0, "next_height": 100 }))
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

async fn handle_get_dao(state: &Arc<AppState>, params: &Value) -> Result<Value, RpcError> {
    let dao_id = params
        .as_array()
        .and_then(|values| values.first())
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "expected DAO id"))?;
    let mut client = NodeClient::connect(state.node_addr)
        .await
        .map_err(|error| node_connection_error(error.to_string()))?;
    match client
        .get_dao(parse_hash(dao_id)?)
        .await
        .map_err(|error| RpcError::new(RpcError::INTERNAL_ERROR, error.to_string()))?
    {
        Some(dao) => serde_json::to_value(dao)
            .map_err(|error| RpcError::new(RpcError::INTERNAL_ERROR, error.to_string())),
        None => Err(RpcError::new(
            RpcError::RESOURCE_NOT_FOUND,
            "DAO was not found",
        )),
    }
}

async fn handle_submit_dao_operation(
    state: &Arc<AppState>,
    params: &Value,
) -> Result<Value, RpcError> {
    let object = params
        .as_object()
        .or_else(|| {
            params
                .as_array()
                .and_then(|values| values.first())
                .and_then(Value::as_object)
        })
        .ok_or_else(|| {
            RpcError::new(
                RpcError::INVALID_PARAMS,
                "expected { action, account? } parameters",
            )
        })?;
    let action: oxydome_core::DaoAction = serde_json::from_value(
        object
            .get("action")
            .cloned()
            .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "missing DAO action"))?,
    )
    .map_err(|error| RpcError::new(RpcError::INVALID_PARAMS, error.to_string()))?;
    let account = object
        .get("account")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        .try_into()
        .map_err(|_| RpcError::new(RpcError::INVALID_PARAMS, "account index is too large"))?;

    let operation = {
        let vault = state.vault.lock().await;
        if !vault.is_unlocked() {
            return Err(RpcError::new(RpcError::VAULT_LOCKED, "vault is locked"));
        }
        let actor = vault
            .derive_key(account, 0)
            .map_err(|error| RpcError::new(RpcError::INVALID_PARAMS, error.to_string()))?;
        let mut operation = oxydome_core::DaoOperation::new_unsigned(actor, action);
        let signature = vault
            .sign_hash(account, 0, &operation.signing_hash().0)
            .map_err(|error| RpcError::new(RpcError::INTERNAL_ERROR, error.to_string()))?;
        operation.signature = oxydome_crypto::Sig(signature);
        if !operation.is_valid() {
            return Err(RpcError::new(
                RpcError::INVALID_PARAMS,
                "DAO action has an invalid shape",
            ));
        }
        operation
    };
    let result_id = operation
        .created_dao_id()
        .map_err(|error| RpcError::new(RpcError::INVALID_PARAMS, error))?
        .unwrap_or_else(|| operation.id());
    let mut client = NodeClient::connect(state.node_addr)
        .await
        .map_err(|error| node_connection_error(error.to_string()))?;
    let (_, accepted, error) = client
        .submit_operation(oxydome_core::Operation::Dao(operation))
        .await
        .map_err(|error| RpcError::new(RpcError::INTERNAL_ERROR, error.to_string()))?;
    if !accepted {
        return Err(RpcError::new(
            RpcError::TX_REJECTED,
            error.unwrap_or_else(|| "DAO operation rejected".into()),
        ));
    }
    Ok(json!(to_hex(result_id.as_bytes())))
}

async fn handle_get_ohm(state: &Arc<AppState>, params: &Value) -> Result<Value, RpcError> {
    let ohm_id = params
        .as_array()
        .and_then(|values| values.first())
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "expected OHM id"))?;
    let ohm_id = parse_hash(ohm_id)?;
    let mut client = NodeClient::connect(state.node_addr)
        .await
        .map_err(|error| node_connection_error(error.to_string()))?;
    match client
        .get_ohm(ohm_id)
        .await
        .map_err(|error| RpcError::new(RpcError::INTERNAL_ERROR, error.to_string()))?
    {
        Some(ohm) => serde_json::to_value(ohm_to_rpc(&ohm_id, &ohm))
            .map_err(|error| RpcError::new(RpcError::INTERNAL_ERROR, error.to_string())),
        None => Err(RpcError::new(
            RpcError::RESOURCE_NOT_FOUND,
            "OHM was not found",
        )),
    }
}

async fn handle_get_ohm_block(state: &Arc<AppState>, params: &Value) -> Result<Value, RpcError> {
    let hash = params
        .as_array()
        .and_then(|values| values.first())
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "expected OHM block hash"))?;
    let mut client = NodeClient::connect(state.node_addr)
        .await
        .map_err(|error| node_connection_error(error.to_string()))?;
    match client
        .get_ohm_block(parse_hash(hash)?)
        .await
        .map_err(|error| RpcError::new(RpcError::INTERNAL_ERROR, error.to_string()))?
    {
        Some(block) => serde_json::to_value(ohm_block_to_rpc(&block))
            .map_err(|error| RpcError::new(RpcError::INTERNAL_ERROR, error.to_string())),
        None => Err(RpcError::new(
            RpcError::RESOURCE_NOT_FOUND,
            "OHM block was not found",
        )),
    }
}

async fn handle_get_ohm_balance(state: &Arc<AppState>, params: &Value) -> Result<Value, RpcError> {
    let values = params
        .as_array()
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "expected [ohm_id, address]"))?;
    let ohm_id = values
        .first()
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "expected OHM id"))?;
    let address = values
        .get(1)
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "expected address"))?;
    let owner = parse_address(address)?;
    let ohm_id = parse_hash(ohm_id)?;
    let mut client = NodeClient::connect(state.node_addr)
        .await
        .map_err(|error| node_connection_error(error.to_string()))?;
    let amount = client
        .get_ohm_balance(ohm_id, owner)
        .await
        .map_err(|error| RpcError::new(RpcError::INTERNAL_ERROR, error.to_string()))?;
    Ok(json!({
        "ohmId": to_hex(ohm_id.as_bytes()),
        "address": address,
        "amount": amount.to_string(),
    }))
}

async fn handle_submit_ohm_operation(
    state: &Arc<AppState>,
    params: &Value,
) -> Result<Value, RpcError> {
    let object = params
        .as_object()
        .or_else(|| {
            params
                .as_array()
                .and_then(|values| values.first())
                .and_then(Value::as_object)
        })
        .ok_or_else(|| {
            RpcError::new(
                RpcError::INVALID_PARAMS,
                "expected { action, account? } parameters",
            )
        })?;
    let action: oxydome_core::OhmAction = serde_json::from_value(
        object
            .get("action")
            .cloned()
            .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "missing OHM action"))?,
    )
    .map_err(|error| RpcError::new(RpcError::INVALID_PARAMS, error.to_string()))?;
    let account = object
        .get("account")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        .try_into()
        .map_err(|_| RpcError::new(RpcError::INVALID_PARAMS, "account index is too large"))?;

    let operation = {
        let vault = state.vault.lock().await;
        if !vault.is_unlocked() {
            return Err(RpcError::new(RpcError::VAULT_LOCKED, "vault is locked"));
        }
        let actor = vault
            .derive_key(account, 0)
            .map_err(|error| RpcError::new(RpcError::INVALID_PARAMS, error.to_string()))?;
        let mut operation = oxydome_core::OhmOperation::new_unsigned(actor, action);
        let signature = vault
            .sign_hash(account, 0, &operation.signing_hash().0)
            .map_err(|error| RpcError::new(RpcError::INTERNAL_ERROR, error.to_string()))?;
        operation.signature = oxydome_crypto::Sig(signature);
        if !operation.is_valid() {
            return Err(RpcError::new(
                RpcError::INVALID_PARAMS,
                "OHM action has an invalid shape",
            ));
        }
        operation
    };
    let result_id = operation
        .created_ohm_id()
        .unwrap_or_else(|| operation.id());
    let mut client = NodeClient::connect(state.node_addr)
        .await
        .map_err(|error| node_connection_error(error.to_string()))?;
    let (_, accepted, error) = client
        .submit_operation(oxydome_core::Operation::Ohm(operation))
        .await
        .map_err(|error| RpcError::new(RpcError::INTERNAL_ERROR, error.to_string()))?;
    if !accepted {
        return Err(RpcError::new(
            RpcError::TX_REJECTED,
            error.unwrap_or_else(|| "OHM operation rejected".into()),
        ));
    }
    Ok(json!(to_hex(result_id.as_bytes())))
}

async fn handle_submit_ohm_block(
    state: &Arc<AppState>,
    params: &Value,
) -> Result<Value, RpcError> {
    let block_value = params
        .as_array()
        .and_then(|values| values.first())
        .cloned()
        .or_else(|| params.as_object().map(|_| params.clone()))
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "expected OHM block"))?;
    let block: oxydome_core::OhmBlock = serde_json::from_value(block_value)
        .map_err(|error| RpcError::new(RpcError::INVALID_PARAMS, error.to_string()))?;
    let hash = block.hash();
    let mut client = NodeClient::connect(state.node_addr)
        .await
        .map_err(|error| node_connection_error(error.to_string()))?;
    let (_, accepted, error) = client
        .submit_ohm_block(block)
        .await
        .map_err(|error| RpcError::new(RpcError::INTERNAL_ERROR, error.to_string()))?;
    if !accepted {
        return Err(RpcError::new(
            RpcError::TX_REJECTED,
            error.unwrap_or_else(|| "OHM block rejected".into()),
        ));
    }
    Ok(json!({
        "hash": to_hex(hash.as_bytes()),
        "accepted": true,
    }))
}

async fn handle_get_ohm_contract(
    state: &Arc<AppState>,
    params: &Value,
) -> Result<Value, RpcError> {
    let values = params
        .as_array()
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "expected [ohm_id, contract_id]"))?;
    let ohm_id = values
        .first()
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "expected OHM id"))?;
    let contract_id = values
        .get(1)
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "expected contract id"))?;
    let ohm_id = parse_hash(ohm_id)?;
    let contract_id = parse_hash(contract_id)?;
    let mut client = NodeClient::connect(state.node_addr)
        .await
        .map_err(|error| node_connection_error(error.to_string()))?;
    match client
        .get_ohm_contract(ohm_id, contract_id)
        .await
        .map_err(|error| RpcError::new(RpcError::INTERNAL_ERROR, error.to_string()))?
    {
        (Some(code), Some(storage)) => serde_json::to_value(ohm_contract_to_rpc(
            &ohm_id,
            &contract_id,
            &code,
            &storage,
        ))
        .map_err(|error| RpcError::new(RpcError::INTERNAL_ERROR, error.to_string())),
        _ => Err(RpcError::new(
            RpcError::RESOURCE_NOT_FOUND,
            "OHM contract was not found",
        )),
    }
}

async fn handle_call_ohm_contract(
    state: &Arc<AppState>,
    params: &Value,
) -> Result<Value, RpcError> {
    let object = params
        .as_object()
        .or_else(|| {
            params
                .as_array()
                .and_then(|values| values.first())
                .and_then(Value::as_object)
        })
        .ok_or_else(|| {
            RpcError::new(
                RpcError::INVALID_PARAMS,
                "expected { ohmId, contractId, entryPoint, arguments?, caller, gasLimit? }",
            )
        })?;
    let ohm_id = object
        .get("ohmId")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "missing OHM id"))?;
    let contract_id = object
        .get("contractId")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "missing contract id"))?;
    let entry_point = object
        .get("entryPoint")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "missing entry point"))?
        .to_string();
    let caller = object
        .get("caller")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "missing caller address"))?;
    let arguments: Vec<u64> = object
        .get("arguments")
        .map(|value| {
            serde_json::from_value(value.clone())
                .map_err(|error| RpcError::new(RpcError::INVALID_PARAMS, error.to_string()))
        })
        .transpose()?
        .unwrap_or_default();
    let gas_limit = object
        .get("gasLimit")
        .map(|value| {
            value
                .as_u64()
                .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "invalid gas limit"))
        })
        .transpose()?
        .unwrap_or(100_000);

    let ohm_id = parse_hash(ohm_id)?;
    let contract_id = parse_hash(contract_id)?;
    let caller = parse_address(caller)?;
    let mut client = NodeClient::connect(state.node_addr)
        .await
        .map_err(|error| node_connection_error(error.to_string()))?;
    let (failure, gas_used, return_value, logs, error) = client
        .call_ohm_contract(
            ohm_id,
            contract_id,
            entry_point,
            arguments,
            caller,
            gas_limit,
        )
        .await
        .map_err(|error| RpcError::new(RpcError::INTERNAL_ERROR, error.to_string()))?;
    if let Some(error) = error {
        return Err(RpcError::new(RpcError::INTERNAL_ERROR, error));
    }
    serde_json::to_value(ohm_contract_call_to_rpc(
        failure,
        gas_used,
        return_value,
        &logs,
    ))
    .map_err(|error| RpcError::new(RpcError::INTERNAL_ERROR, error.to_string()))
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

    let ovm_action = obj
        .get("ovmAction")
        .map(|value| {
            let action = value.as_object().ok_or_else(|| {
                RpcError::new(RpcError::INVALID_PARAMS, "ovmAction must be an object")
            })?;
            let kind = action.get("kind").and_then(Value::as_str).ok_or_else(|| {
                RpcError::new(RpcError::INVALID_PARAMS, "missing OVM action kind")
            })?;
            let gas_limit = action
                .get("gasLimit")
                .and_then(Value::as_u64)
                .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "missing OVM gasLimit"))?;
            match kind {
                "deploy" => {
                    let code = action
                        .get("code")
                        .and_then(Value::as_str)
                        .and_then(parse_hex)
                        .ok_or_else(|| {
                            RpcError::new(RpcError::INVALID_PARAMS, "invalid OVM code")
                        })?;
                    Ok(oxydome_core::OvmAction::Deploy { code, gas_limit })
                }
                "deployContract" => {
                    let artifact = action
                        .get("artifact")
                        .and_then(Value::as_str)
                        .and_then(parse_hex)
                        .ok_or_else(|| {
                            RpcError::new(
                                RpcError::INVALID_PARAMS,
                                "invalid smart-contract artifact",
                            )
                        })?;
                    Ok(oxydome_core::OvmAction::DeployContract {
                        artifact,
                        gas_limit,
                    })
                }
                "call" => {
                    let contract_id = action
                        .get("contractId")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            RpcError::new(RpcError::INVALID_PARAMS, "missing contractId")
                        })?;
                    let arguments = action
                        .get("arguments")
                        .and_then(Value::as_array)
                        .ok_or_else(|| {
                            RpcError::new(RpcError::INVALID_PARAMS, "missing OVM arguments")
                        })?
                        .iter()
                        .map(|argument| {
                            argument.as_u64().ok_or_else(|| {
                                RpcError::new(
                                    RpcError::INVALID_PARAMS,
                                    "OVM arguments must be unsigned integers",
                                )
                            })
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    Ok(oxydome_core::OvmAction::Call {
                        contract_id: parse_hash(contract_id)?,
                        arguments,
                        gas_limit,
                    })
                }
                "callContract" => {
                    let contract_id = action
                        .get("contractId")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            RpcError::new(RpcError::INVALID_PARAMS, "missing contractId")
                        })?;
                    let entry_point = action
                        .get("entryPoint")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            RpcError::new(RpcError::INVALID_PARAMS, "missing entryPoint")
                        })?
                        .to_owned();
                    let arguments = action
                        .get("arguments")
                        .and_then(Value::as_array)
                        .ok_or_else(|| {
                            RpcError::new(RpcError::INVALID_PARAMS, "missing OVM arguments")
                        })?
                        .iter()
                        .map(|argument| {
                            argument.as_u64().ok_or_else(|| {
                                RpcError::new(
                                    RpcError::INVALID_PARAMS,
                                    "OVM arguments must be unsigned integers",
                                )
                            })
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    let authority_input = action
                        .get("authorityInput")
                        .and_then(Value::as_u64)
                        .and_then(|value| u32::try_from(value).ok())
                        .ok_or_else(|| {
                            RpcError::new(
                                RpcError::INVALID_PARAMS,
                                "missing or invalid authorityInput",
                            )
                        })?;
                    Ok(oxydome_core::OvmAction::CallContract {
                        contract_id: parse_hash(contract_id)?,
                        entry_point,
                        arguments,
                        authority_input,
                        gas_limit,
                    })
                }
                _ => Err(RpcError::new(
                    RpcError::INVALID_PARAMS,
                    "OVM action kind must be deploy, call, deployContract, or callContract",
                )),
            }
        })
        .transpose()?;

    Ok(oxydome_core::Transaction {
        inputs,
        outputs,
        fee,
        ovm_action,
        ohm_context: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_named_contract_calls_with_optional_simulation_caller() {
        let params = json!({
            "contractId": format!("0x{}", "11".repeat(64)),
            "entryPoint": "balanceOf",
            "arguments": [9],
        });
        let (contract_id, entry_point, arguments, caller, gas_limit) =
            parse_ovm_contract_call(&params).unwrap();
        assert_eq!(contract_id, oxydome_core::Hash([0x11; 64]));
        assert_eq!(entry_point, "balanceOf");
        assert_eq!(arguments, vec![9]);
        assert_eq!(caller, oxydome_core::PublicKey::from_bytes([0; 32]));
        assert_eq!(gas_limit, oxydome_core::tx::MAX_OVM_GAS_LIMIT);

        let params = json!({
            "contractId": format!("0x{}", "22".repeat(64)),
            "entryPoint": "set",
            "arguments": [],
            "from": format!("0x{}", "33".repeat(32)),
            "gasLimit": 50,
        });
        let (_, _, _, caller, gas_limit) = parse_ovm_contract_call(&params).unwrap();
        assert_eq!(caller, oxydome_core::PublicKey::from_bytes([0x33; 32]));
        assert_eq!(gas_limit, 50);
    }

    #[test]
    fn rejects_named_contract_calls_that_exceed_authority_argument_bounds() {
        let params = json!({
            "contractId": format!("0x{}", "11".repeat(64)),
            "entryPoint": "tooMany",
            "arguments": vec![0; oxydome_ovm::MAX_ARGUMENTS - oxydome_ovm::AUTHORITY_WORD_COUNT + 1],
        });
        assert!(parse_ovm_contract_call(&params).is_err());
    }

    #[test]
    fn parses_signed_smart_contract_transaction_actions() {
        let transaction = parse_rpc_transaction(&json!({
            "inputs": [],
            "outputs": [],
            "fee": "1",
            "ovmAction": {
                "kind": "callContract",
                "contractId": format!("0x{}", "44".repeat(64)),
                "entryPoint": "transfer",
                "arguments": [5, 8],
                "authorityInput": 0,
                "gasLimit": 500,
            },
        }))
        .unwrap();
        assert_eq!(
            transaction.ovm_action,
            Some(oxydome_core::OvmAction::CallContract {
                contract_id: oxydome_core::Hash([0x44; 64]),
                entry_point: "transfer".into(),
                arguments: vec![5, 8],
                authority_input: 0,
                gas_limit: 500,
            })
        );
    }
}
