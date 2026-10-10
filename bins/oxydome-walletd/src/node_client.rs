//! TCP client for communicating with an Oxydome node via the binary wire protocol.

use oxydome_core::{Block, Hash, OutPoint, PublicKey, Transaction};
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
