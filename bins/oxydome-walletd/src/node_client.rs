//! TCP client for communicating with an Oxydome node via the binary wire protocol.

use oxydome_core::{
    Amount, Block, DaoState, Hash, OhmBlock, OhmState, Operation, OutPoint, OvmFailureCode, OvmLog,
    PublicKey, Transaction,
};
use oxydome_crypto::SparseProof;
use oxydome_net::{
    recv_message, send_message, BalanceInfo, HistoryEntry, Message, NetError, TxLocation, TxStatus,
    UtxoEntry, UtxoInfo, ValueIndexInfo,
};
use std::net::SocketAddr;
use tokio::net::TcpStream;

/// A connected client session to a node.
pub struct NodeClient {
    stream: TcpStream,
}

impl NodeClient {
    /// Connects to a node at `addr`.
    pub async fn connect(addr: SocketAddr) -> Result<Self, NetError> {
        let stream = TcpStream::connect(addr).await?;
        Ok(Self { stream })
    }

    /// Sends a request and waits for the response.
    async fn request(&mut self, req: &Message) -> Result<Message, NetError> {
        send_message(&mut self.stream, req).await?;
        loop {
            match recv_message(&mut self.stream).await? {
                Message::Ping { nonce } => {
                    send_message(&mut self.stream, &Message::Pong { nonce }).await?;
                }
                reply => return Ok(reply),
            }
        }
    }

    /// Fetches the balance for `owner`.
    pub async fn get_balance(&mut self, owner: PublicKey) -> Result<BalanceInfo, NetError> {
        match self.request(&Message::GetBalance { owner }).await? {
            Message::BalanceResponse { info } => Ok(info),
            other => Err(NetError::Unexpected(format!("{other:?}"))),
        }
    }

    /// Fetches UTXOs for `owner`.
    pub async fn get_utxos(&mut self, owner: PublicKey) -> Result<Vec<UtxoInfo>, NetError> {
        match self.request(&Message::GetUtxos { owner }).await? {
            Message::UtxosResponse { entries } => Ok(entries),
            other => Err(NetError::Unexpected(format!("{other:?}"))),
        }
    }

    /// Fetches a UTXO inclusion proof.
    pub async fn get_utxo_proof(
        &mut self,
        outpoint: OutPoint,
    ) -> Result<(Option<UtxoEntry>, Option<SparseProof>), NetError> {
        match self.request(&Message::GetUtxoProof { outpoint }).await? {
            Message::UtxoProofResponse { entry, proof } => Ok((entry, proof)),
            other => Err(NetError::Unexpected(format!("{other:?}"))),
        }
    }

    /// Fetches a block by height.
    pub async fn get_block_by_height(&mut self, height: u64) -> Result<Option<Block>, NetError> {
        match self.request(&Message::GetBlockByHeight { height }).await? {
            Message::BlockByHeightResponse { block } => Ok(block.map(|b| *b)),
            other => Err(NetError::Unexpected(format!("{other:?}"))),
        }
    }

    /// Fetches a transaction and its status.
    pub async fn get_transaction(
        &mut self,
        txid: Hash,
    ) -> Result<(Option<Transaction>, Option<TxLocation>, TxStatus), NetError> {
        match self.request(&Message::GetTransaction { txid }).await? {
            Message::TransactionResponse {
                tx,
                location,
                status,
            } => Ok((tx.map(|t| *t), location, status)),
            other => Err(NetError::Unexpected(format!("{other:?}"))),
        }
    }

    /// Fetches wallet history.
    pub async fn get_history(
        &mut self,
        owner: PublicKey,
        cursor: u64,
        limit: u32,
    ) -> Result<(Vec<HistoryEntry>, u64), NetError> {
        match self
            .request(&Message::GetHistory {
                owner,
                cursor,
                limit,
            })
            .await?
        {
            Message::HistoryResponse {
                entries,
                next_cursor,
            } => Ok((entries, next_cursor)),
            other => Err(NetError::Unexpected(format!("{other:?}"))),
        }
    }

    /// Fetches the value index snapshot.
    pub async fn get_value_index(&mut self) -> Result<ValueIndexInfo, NetError> {
        match self.request(&Message::GetValueIndex).await? {
            Message::ValueIndexResponse { info } => Ok(info),
            other => Err(NetError::Unexpected(format!("{other:?}"))),
        }
    }

    /// Submits a transaction.
    pub async fn submit_transaction(
        &mut self,
        tx: Transaction,
    ) -> Result<(Hash, bool, Option<String>), NetError> {
        match self
            .request(&Message::SubmitTransaction { tx: Box::new(tx) })
            .await?
        {
            Message::SubmitResponse {
                txid,
                accepted,
                error,
            } => Ok((txid, accepted, error)),
            other => Err(NetError::Unexpected(format!("{other:?}"))),
        }
    }

    pub async fn submit_operation(
        &mut self,
        operation: Operation,
    ) -> Result<(Hash, bool, Option<String>), NetError> {
        match self
            .request(&Message::SubmitOperation {
                operation: Box::new(operation),
            })
            .await?
        {
            Message::OperationSubmitResponse {
                operation_id,
                accepted,
                error,
            } => Ok((operation_id, accepted, error)),
            other => Err(NetError::Unexpected(format!("{other:?}"))),
        }
    }

    pub async fn get_dao(&mut self, dao_id: Hash) -> Result<Option<DaoState>, NetError> {
        match self.request(&Message::GetDao { dao_id }).await? {
            Message::DaoResponse { state, .. } => Ok(state),
            other => Err(NetError::Unexpected(format!("{other:?}"))),
        }
    }

    /// Fetches the Ox-committed anchor state for `ohm_id`.
    pub async fn get_ohm(&mut self, ohm_id: Hash) -> Result<Option<OhmState>, NetError> {
        match self.request(&Message::GetOhm { ohm_id }).await? {
            Message::OhmResponse { state, .. } => Ok(state.map(|s| *s)),
            other => Err(NetError::Unexpected(format!("{other:?}"))),
        }
    }

    /// Fetches a private OHM block body by hash.
    pub async fn get_ohm_block(&mut self, hash: Hash) -> Result<Option<OhmBlock>, NetError> {
        match self.request(&Message::GetOhmBlock { hash }).await? {
            Message::OhmBlockResponse { block } => Ok(block.map(|b| *b)),
            other => Err(NetError::Unexpected(format!("{other:?}"))),
        }
    }

    /// Fetches the OHM-local balance of `owner` within `ohm_id`.
    pub async fn get_ohm_balance(
        &mut self,
        ohm_id: Hash,
        owner: PublicKey,
    ) -> Result<Amount, NetError> {
        match self.request(&Message::GetOhmBalance { ohm_id, owner }).await? {
            Message::OhmBalanceResponse { amount, .. } => Ok(amount),
            other => Err(NetError::Unexpected(format!("{other:?}"))),
        }
    }

    /// Submits a private OHM block.
    pub async fn submit_ohm_block(
        &mut self,
        block: OhmBlock,
    ) -> Result<(Hash, bool, Option<String>), NetError> {
        match self
            .request(&Message::SubmitOhmBlock {
                block: Box::new(block),
            })
            .await?
        {
            Message::OhmBlockSubmitResponse {
                hash,
                accepted,
                error,
            } => Ok((hash, accepted, error)),
            other => Err(NetError::Unexpected(format!("{other:?}"))),
        }
    }

    /// Fetches an OHM-hosted contract's code and storage.
    pub async fn get_ohm_contract(
        &mut self,
        ohm_id: Hash,
        contract_id: Hash,
    ) -> Result<(Option<Vec<u8>>, Option<Vec<(u64, u64)>>), NetError> {
        match self
            .request(&Message::GetOhmContract {
                ohm_id,
                contract_id,
            })
            .await?
        {
            Message::OhmContractResponse { code, storage, .. } => Ok((code, storage)),
            other => Err(NetError::Unexpected(format!("{other:?}"))),
        }
    }

    /// Simulates an OHM-hosted contract call.
    #[allow(clippy::type_complexity)]
    pub async fn call_ohm_contract(
        &mut self,
        ohm_id: Hash,
        contract_id: Hash,
        entry_point: String,
        arguments: Vec<u64>,
        caller: PublicKey,
        gas_limit: u64,
    ) -> Result<
        (
            Option<OvmFailureCode>,
            u64,
            Option<u64>,
            Vec<OvmLog>,
            Option<String>,
        ),
        NetError,
    > {
        match self
            .request(&Message::CallOhmContract {
                ohm_id,
                contract_id,
                entry_point,
                arguments,
                caller,
                gas_limit,
            })
            .await?
        {
            Message::OhmContractCallResponse {
                failure,
                gas_used,
                return_value,
                logs,
                error,
            } => Ok((failure, gas_used, return_value, logs, error)),
            other => Err(NetError::Unexpected(format!("{other:?}"))),
        }
    }

    pub async fn get_ovm_code(&mut self, contract_id: Hash) -> Result<Option<Vec<u8>>, NetError> {
        match self.request(&Message::GetOvmCode { contract_id }).await? {
            Message::OvmCodeResponse { code } => Ok(code),
            other => Err(NetError::Unexpected(format!("{other:?}"))),
        }
    }

    pub async fn call_ovm(
        &mut self,
        contract_id: Hash,
        arguments: Vec<u64>,
        gas_limit: u64,
    ) -> Result<oxydome_ovm::Execution, String> {
        match self
            .request(&Message::CallOvm {
                contract_id,
                arguments,
                gas_limit,
            })
            .await
            .map_err(|error| error.to_string())?
        {
            Message::OvmCallResponse {
                execution: Some(execution),
                error: None,
            } => Ok(execution),
            Message::OvmCallResponse {
                error: Some(error), ..
            } => Err(error),
            other => Err(format!("unexpected node response: {other:?}")),
        }
    }

    pub async fn call_ovm_contract(
        &mut self,
        contract_id: Hash,
        entry_point: String,
        arguments: Vec<u64>,
        caller: PublicKey,
        gas_limit: u64,
    ) -> Result<oxydome_ovm::Execution, String> {
        match self
            .request(&Message::CallOvmContract {
                contract_id,
                entry_point,
                arguments,
                caller,
                gas_limit,
            })
            .await
            .map_err(|error| error.to_string())?
        {
            Message::OvmContractCallResponse {
                execution: Some(execution),
                error: None,
            } => Ok(execution),
            Message::OvmContractCallResponse {
                error: Some(error), ..
            } => Err(error),
            other => Err(format!("unexpected node response: {other:?}")),
        }
    }

    pub async fn get_content(&mut self, hash: Hash) -> Result<Option<Vec<u8>>, NetError> {
        match self
            .request(&Message::GetContent {
                hash,
                hops_remaining: 4,
            })
            .await?
        {
            Message::ContentResponse { content } => Ok(content),
            other => Err(NetError::Unexpected(format!("{other:?}"))),
        }
    }

    pub async fn store_content(&mut self, content: Vec<u8>) -> Result<Hash, String> {
        if content.len() as u64 > oxydome_ovm::MAX_ASSET_BYTES {
            return Err("content exceeds the per-item asset size limit".into());
        }
        let hash = oxydome_ovm::content_hash(&content);
        match self
            .request(&Message::StoreContent { hash, content })
            .await
            .map_err(|error| error.to_string())?
        {
            Message::StoreContentResponse {
                stored: true,
                error: None,
            } => Ok(hash),
            Message::StoreContentResponse {
                error: Some(error), ..
            } => Err(error),
            other => Err(format!("unexpected node response: {other:?}")),
        }
    }
}
