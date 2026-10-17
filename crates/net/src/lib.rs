//! Networking for Oxydome: the wire message set, a length-framed TCP transport and
//! round-trip-time based nearest-master selection.

use oxydome_audit::{AuditAttestation, AuditPackage};
use oxydome_consensus::{AdmissionCertificate, MasterCheck, QuorumCertificate, Vote};
use oxydome_core::{
    Amount, Block, DaoState, Hash, InboundReceipt, OhmBlock, OhmState, Operation, OutPoint,
    OutboundMessage, OutputKind, OvmFailureCode, OvmLog, PublicKey, Transaction,
};
use oxydome_crypto::{CodeManifest, SparseProof};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub mod secure_channel;
pub use secure_channel::PeerAdminSecureLink;

/// Maximum accepted frame size (16 MiB).
pub const MAX_FRAME: usize = 16 * 1024 * 1024;

/// Networking errors.
#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("codec error: {0}")]
    Codec(String),
    #[error("frame too large: {0} bytes")]
    FrameTooLarge(usize),
    #[error("no reachable master")]
    NoMaster,
    #[error("unexpected message: {0}")]
    Unexpected(String),
}

/// Every message that can travel the Oxydome wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    // -- liveness --
    Ping {
        nonce: u64,
    },
    Pong {
        nonce: u64,
    },

    // -- chain handshake & validation --
    Handshake {
        chain_id: String,
        version: u32,
    },
    HandshakeResponse {
        accepted: bool,
        chain_id: String,
        error: Option<String>,
    },

    // -- admission (node <-> master) --
    AdmitRequest {
        node: PublicKey,
        manifest_root: Hash,
        manifest: CodeManifest,
        nonce: u64,
        timestamp: u64,
        #[serde(default)]
        chain_id: Option<String>,
    },
    AdmitResponse {
        certificate: Option<Box<AdmissionCertificate>>,
        reason: Option<String>,
        #[serde(default)]
        chain_id: Option<String>,
    },
    ManifestsResponse {
        approved: Vec<Hash>,
    },

    // -- master governance --
    MasterProposalBroadcast {
        candidate: PublicKey,
        proposer: PublicKey,
    },
    EpochTransitionBroadcast {
        epoch: u64,
        masters: Vec<PublicKey>,
    },

    // -- consensus (node <-> node) --
    Proposal {
        block: Block,
        package: AuditPackage,
    },
    Attestation {
        attestation: AuditAttestation,
    },
    VoteMessage {
        vote: Vote,
    },
    QuorumCertificateMessage {
        certificate: QuorumCertificate,
    },
    MasterCheckMessage {
        check: MasterCheck,
    },

    // -- wallet queries (walletd <-> node) --
    GetBalance {
        owner: PublicKey,
    },
    BalanceResponse {
        info: BalanceInfo,
    },
    GetUtxos {
        owner: PublicKey,
    },
    UtxosResponse {
        entries: Vec<UtxoInfo>,
    },
    GetUtxoProof {
        outpoint: OutPoint,
    },
    UtxoProofResponse {
        entry: Option<UtxoEntry>,
        proof: Option<SparseProof>,
    },
    GetBlockByHeight {
        height: u64,
    },
    BlockByHeightResponse {
        block: Option<Box<Block>>,
    },
    GetTransaction {
        txid: Hash,
    },
    TransactionResponse {
        tx: Option<Box<Transaction>>,
        location: Option<TxLocation>,
        status: TxStatus,
    },
    GetHistory {
        owner: PublicKey,
        cursor: u64,
        limit: u32,
    },
    HistoryResponse {
        entries: Vec<HistoryEntry>,
        next_cursor: u64,
    },
    GetValueIndex,
    ValueIndexResponse {
        info: ValueIndexInfo,
    },
    SubmitTransaction {
        tx: Box<Transaction>,
    },
    SubmitResponse {
        txid: Hash,
        accepted: bool,
        error: Option<String>,
    },
    SubmitOperation {
        operation: Box<Operation>,
    },
    OperationSubmitResponse {
        operation_id: Hash,
        accepted: bool,
        error: Option<String>,
    },
    GetDao {
        dao_id: Hash,
    },
    DaoResponse {
        dao_id: Hash,
        state: Option<DaoState>,
    },
    // -- OHM (walletd/clients <-> node) --
    GetOhm {
        ohm_id: Hash,
    },
    OhmResponse {
        ohm_id: Hash,
        state: Option<Box<OhmState>>,
    },
    GetOhmBlock {
        hash: Hash,
    },
    OhmBlockResponse {
        block: Option<Box<OhmBlock>>,
    },
    GetOhmBalance {
        ohm_id: Hash,
        owner: PublicKey,
    },
    OhmBalanceResponse {
        ohm_id: Hash,
        amount: Amount,
    },
    SubmitOhmBlock {
        block: Box<OhmBlock>,
    },
    OhmBlockSubmitResponse {
        hash: Hash,
        accepted: bool,
        error: Option<String>,
    },
    GetOhmContract {
        ohm_id: Hash,
        contract_id: Hash,
    },
    OhmContractResponse {
        ohm_id: Hash,
        contract_id: Hash,
        code: Option<Vec<u8>>,
        storage: Option<Vec<(u64, u64)>>,
    },
    CallOhmContract {
        ohm_id: Hash,
        contract_id: Hash,
        entry_point: String,
        arguments: Vec<u64>,
        caller: PublicKey,
        gas_limit: u64,
    },
    OhmContractCallResponse {
        failure: Option<OvmFailureCode>,
        gas_used: u64,
        return_value: Option<u64>,
        logs: Vec<OvmLog>,
        error: Option<String>,
    },
    GetOhmOutbox {
        ohm_id: Hash,
    },
    OhmOutboxResponse {
        ohm_id: Hash,
        messages: Vec<OutboundMessage>,
    },
    GetOhmInbox {
        ohm_id: Hash,
    },
    OhmInboxResponse {
        ohm_id: Hash,
        receipts: Vec<InboundReceipt>,
    },
    // -- GAS (walletd <-> node) --
    GetGasBalance {
        owner: PublicKey,
    },
    GasBalanceResponse {
        amount: Amount,
    },
    GetGasSupply,
    GasSupplyResponse {
        amount: Amount,
    },
    GetGasPrice,
    GasPriceResponse,
    GetGasAirdropInfo,
    GasAirdropInfoResponse {
        height: u64,
    },
    GetOvmCode {
        contract_id: Hash,
    },
    OvmCodeResponse {
        code: Option<Vec<u8>>,
    },
    CallOvm {
        contract_id: Hash,
        arguments: Vec<u64>,
        gas_limit: u64,
    },
    OvmCallResponse {
        execution: Option<oxydome_ovm::Execution>,
        error: Option<String>,
    },
    CallOvmContract {
        contract_id: Hash,
        entry_point: String,
        arguments: Vec<u64>,
        caller: PublicKey,
        gas_limit: u64,
    },
    OvmContractCallResponse {
        execution: Option<oxydome_ovm::Execution>,
        error: Option<String>,
    },
    GetContent {
        hash: Hash,
        hops_remaining: u8,
    },
    ContentResponse {
        content: Option<Vec<u8>>,
    },
    StoreContent {
        hash: Hash,
        content: Vec<u8>,
    },
    StoreContentResponse {
        stored: bool,
        error: Option<String>,
    },

    // -- wallet subscriptions (walletd <-> node) --
    Subscribe {
        kinds: Vec<WalletSubscription>,
    },
    SubscribeResponse {
        ok: bool,
        error: Option<String>,
    },
    Unsubscribe,
    Event {
        event: NodeEvent,
    },

    // -- chain sync --
    GetHeaders {
        from_height: u64,
    },
    HeadersResponse {
        blocks: Vec<Block>,
    },
    /// A finalized block being broadcast to masters (who keep headers) and peers (who sync).
    FinalizedBlock {
        finalized: Box<FinalizedBlockRecord>,
    },
    GetFinalizedBlocks {
        from_height: u64,
        limit: u8,
    },
    FinalizedBlocksResponse {
        blocks: Vec<FinalizedBlockRecord>,
        tip_height: u64,
        error: Option<String>,
    },
    /// Request for a node's storage label.
    StorageLabelRequest {
        nonce: u64,
    },
    /// Response containing a node's storage label.
    StorageLabelResponse {
        label: oxydome_core::StorageLabel,
    },
    // -- timers --
    /// Query for a timer by id.
    GetTimer {
        timer_id: Hash,
    },
    TimerResponse {
        timer: Option<oxydome_core::Timer>,
    },
    /// Query for all active (unresolved) timers.
    GetActiveTimers,
    ActiveTimersResponse {
        timers: Vec<oxydome_core::Timer>,
    },
    /// Query for a specific better's bets.
    GetTimerBets {
        better: PublicKey,
    },
    TimerBetsResponse {
        bets: Vec<oxydome_core::TimerBet>,
    },
    // -- EVFS file system --
    /// Query for a file label by its key chain commitment.
    GetFileLabel {
        key_chain_commitment: Hash,
    },
    /// Response containing a file label, if present.
    FileLabelResponse {
        label: Option<oxydome_core::FileEvkLabel>,
    },
    /// Query for the access log of a file.
    GetFileAccessLog {
        file_id: Hash,
    },
    /// Response with access records for a file.
    FileAccessLogResponse {
        records: Vec<oxydome_core::FileAccessRecord>,
    },
    /// Query for a node's file root, count and storage.
    GetNodeFileRoot {
        node: PublicKey,
    },
    /// Response with a node's file system state.
    NodeFileRootResponse {
        file_root: Option<Hash>,
        file_count: u64,
        file_storage_bytes: u64,
    },
}

/// Evidence accompanying a finalized block. Recipients must verify every quorum and
/// independently execute the block before advancing full-node state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalityEvidence {
    pub attestations: Vec<AuditAttestation>,
    pub prepare_qc: QuorumCertificate,
    pub commit_qc: QuorumCertificate,
    pub master_checks: Vec<MasterCheck>,
}

/// A block plus the consensus evidence required to safely relay it to another node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalizedBlockRecord {
    pub block: Block,
    pub evidence: FinalityEvidence,
}

/// A wallet's balances, split by output class, at the queried height.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BalanceInfo {
    /// Sum of mature ordinary (spendable) outputs.
    pub spendable: Amount,
    /// Sum of locked reward outputs (unlockable via an approved withdrawal operation).
    pub locked_reward: Amount,
    /// Sum deposited into the Exit/Reserve sink.
    pub exit_reserve: Amount,
    /// Block height at which the snapshot was taken.
    pub height: u64,
}

/// A single UTXO belonging to a wallet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UtxoInfo {
    pub outpoint: OutPoint,
    pub amount: Amount,
    pub recipient: PublicKey,
    pub kind: OutputKind,
    pub created_height: u64,
    /// Whether the output satisfies the rebound maturity rule at the current tip.
    pub mature: bool,
}

/// A single unspent transaction output plus its creation metadata (re-exported for wallet clients).
pub use oxydome_state::UtxoEntry;
/// Where a transaction sits in the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxLocation {
    pub height: u64,
    pub block_hash: Hash,
    pub position: u32,
}

/// The on-chain lifecycle state of a transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TxStatus {
    Pending,
    Confirmed { height: u64 },
    Rejected { reason: String },
    Unknown,
}

/// A single wallet-relevant event in a block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub txid: Hash,
    pub height: u64,
    pub block_hash: Hash,
    pub position: u32,
    /// Total value credited to the wallet (its outputs in this transaction).
    pub in_amount: Amount,
    /// Total value debited from the wallet (its inputs consumed by this transaction).
    pub out_amount: Amount,
}

/// Subscription channels a wallet can open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WalletSubscription {
    /// Every newly committed block.
    NewBlocks,
    /// A transaction entered the wallet's mempool.
    TxAccepted,
    /// A previously accepted transaction was confirmed in a block.
    TxConfirmed,
    /// A previously accepted transaction was rejected (conflict/spend).
    TxRejected,
    /// The wallet's balances changed as a result of a committed block.
    BalanceChanged,
    /// A transaction entered or left the wallet's mempool.
    Mempool,
}

/// An asynchronous event streamed to wallets that hold a matching subscription.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeEvent {
    BlockCommitted {
        height: u64,
        block_hash: Hash,
        txids: Vec<Hash>,
    },
    TxAccepted {
        txid: Hash,
        addresses: Vec<PublicKey>,
    },
    TxConfirmed {
        txid: Hash,
        location: TxLocation,
        addresses: Vec<PublicKey>,
    },
    TxRejected {
        txid: Hash,
        reason: String,
        addresses: Vec<PublicKey>,
    },
    /// A transaction entered or left the mempool.
    MempoolChanged {
        txid: Hash,
        added: bool,
        addresses: Vec<PublicKey>,
    },
}

/// Snapshot of the chain's value index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValueIndexInfo {
    pub value_index: u128,
    pub generation: u64,
    pub supply: Amount,
    pub height: u64,
}

/// Serializes a message to bytes.
pub fn encode_message(msg: &Message) -> Result<Vec<u8>, NetError> {
    bincode::serialize(msg).map_err(|e| NetError::Codec(e.to_string()))
}

/// Deserializes a message from bytes.
pub fn decode_message(bytes: &[u8]) -> Result<Message, NetError> {
    bincode::deserialize(bytes).map_err(|e| NetError::Codec(e.to_string()))
}

/// Sends a length-framed message over a TCP stream.
pub async fn send_message(stream: &mut TcpStream, msg: &Message) -> Result<(), NetError> {
    let bytes = encode_message(msg)?;
    if bytes.len() > MAX_FRAME {
        return Err(NetError::FrameTooLarge(bytes.len()));
    }
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .await?;
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    Ok(())
}

/// Receives a length-framed message from a TCP stream.
pub async fn recv_message(stream: &mut TcpStream) -> Result<Message, NetError> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        return Err(NetError::FrameTooLarge(len));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    decode_message(&buf)
}

/// Measures the round-trip time to `addr` with a single ping/pong.
pub async fn measure_rtt(addr: SocketAddr) -> Result<Duration, NetError> {
    let mut stream = TcpStream::connect(addr).await?;
    let nonce: u64 = 0xD0D0_1234_5678;
    let start = Instant::now();
    send_message(&mut stream, &Message::Ping { nonce }).await?;
    loop {
        match recv_message(&mut stream).await? {
            Message::Pong { nonce: n } if n == nonce => {
                return Ok(start.elapsed());
            }
            _ => continue,
        }
    }
}

/// A master's network location.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MasterEndpoint {
    pub key: PublicKey,
    pub addr: SocketAddr,
}

/// Returns the reachable master with the smallest round-trip time.
pub async fn nearest_master(masters: &[MasterEndpoint]) -> Result<MasterEndpoint, NetError> {
    let mut best: Option<(Duration, MasterEndpoint)> = None;
    for master in masters {
        if let Ok(rtt) = measure_rtt(master.addr).await {
            match &best {
                Some((best_rtt, _)) if *best_rtt <= rtt => {}
                _ => best = Some((rtt, *master)),
            }
        }
    }
    best.map(|(_, m)| m).ok_or(NetError::NoMaster)
}

/// Serves a single ping/pong exchange; returns true if the peer is still connected.
pub async fn serve_ping(stream: &mut TcpStream, msg: &Message) -> Result<bool, NetError> {
    if let Message::Ping { nonce } = msg {
        send_message(stream, &Message::Pong { nonce: *nonce }).await?;
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Validates that an incoming peer's chain ID matches local chain ID.
pub fn validate_chain_handshake(local_chain_id: &str, peer_chain_id: &str) -> Result<(), NetError> {
    if local_chain_id == peer_chain_id {
        Ok(())
    } else {
        Err(NetError::Unexpected(format!(
            "peer chain mismatch: local is '{}', peer is '{}'",
            local_chain_id, peer_chain_id
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_chain_handshake() {
        assert!(validate_chain_handshake("mychain-mygas-1234", "mychain-mygas-1234").is_ok());
        assert!(validate_chain_handshake("mychain-mygas-1234", "otherchain-ox-5678").is_err());
    }

    #[test]
    fn test_handshake_message_serde() {
        let msg = Message::Handshake {
            chain_id: "testchain-tox-123".to_string(),
            version: 1,
        };
        let encoded = bincode::serialize(&msg).expect("serialize");
        let decoded: Message = bincode::deserialize(&encoded).expect("deserialize");
        match decoded {
            Message::Handshake { chain_id, version } => {
                assert_eq!(chain_id, "testchain-tox-123");
                assert_eq!(version, 1);
            }
            _ => panic!("wrong message variant"),
        }
    }
}
