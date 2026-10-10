//! Networking for Oxydome: the wire message set, a length-framed TCP transport and
//! round-trip-time based nearest-master selection.

use oxydome_audit::{AuditAttestation, AuditPackage};
use oxydome_consensus::{AdmissionCertificate, MasterCheck, QuorumCertificate, Vote};
use oxydome_core::{Amount, Block, Hash, OutPoint, OutputKind, PublicKey, Transaction};
use oxydome_crypto::{CodeManifest, SparseProof};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

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

    // -- admission (node <-> master) --
    AdmitRequest {
        node: PublicKey,
        manifest_root: Hash,
        manifest: CodeManifest,
        nonce: u64,
        timestamp: u64,
    },
    AdmitResponse {
        certificate: Option<Box<AdmissionCertificate>>,
        reason: Option<String>,
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
        block: Block,
    },
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
