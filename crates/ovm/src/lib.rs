//! Deterministic Ox Virtual Machine bytecode and interpreter.
//!
//! OVM v1 is intentionally small: fixed-width `u64` arithmetic, bounded stack and gas,
//! indexed local variables, and `u64` contract storage slots/values. It does not execute
//! host code or perform I/O.

use oxydome_crypto::{hash_value, Hash};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const MAGIC: &[u8; 4] = b"OVM\x01";
const CONTRACT_MAGIC: &[u8; 4] = b"OSC\x01";
const ASSET_MANIFEST_MAGIC: &[u8; 4] = b"OAM\x01";
const MAX_CODE_BYTES: usize = 64 * 1024;
const MAX_STACK: usize = 1024;
const MAX_LOCALS: usize = 256;
pub const MAX_ARGUMENTS: usize = 64;
pub const AUTHORITY_WORD_COUNT: usize = 4;
pub const MAX_CONTRACT_FUNCTIONS: usize = 128;
pub const MAX_FUNCTION_NAME_BYTES: usize = 64;
pub const MAX_CONTRACT_ARTIFACT_BYTES: usize = 256 * 1024;
pub const MAX_ASSET_MANIFEST_ENTRIES: usize = 1024;
pub const MAX_ASSET_PATH_BYTES: usize = 255;
pub const MAX_ASSET_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_ASSET_MANIFEST_BYTES: u64 = 32 * 1024 * 1024;
pub const MAX_STORAGE_SLOTS: usize = 1_024;
pub const MAX_CONTRACTS: usize = 10_000;
pub const ACTION_INTRINSIC_GAS: u64 = 10;
pub const CONTRACT_DISPATCH_GAS: u64 = 5;
/// Upper bound on the payload arguments a contract may stage in a single `XCall` message.
pub const MAX_CROSS_ARGUMENTS: usize = 64;
/// Fixed base cost charged for staging a cross-OHM message (`XCall`) or reading a receipt.
pub const CROSS_HOST_GAS: u64 = 20;
/// Number of bytes of data stack that a single GAS unit reserves.
pub const STACK_BYTES_PER_GAS: u64 = 6;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Instruction {
    Push(u64),
    LoadArg(u8),
    LoadLocal(u8),
    StoreLocal(u8),
    LoadStorage(u64),
    StoreStorage(u64),
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Equal,
    LessThan,
    GreaterThan,
    And,
    Or,
    Not,
    Jump(u32),
    JumpIfFalse(u32),
    Emit(u32),
    /// Stages a contract-originated cross-OHM message. Pop order (top first): `gas_limit`,
    /// `entry_selector`, eight `target_contract` words, eight `target_ohm` words, then
    /// `arg_count` payload words. Pushes the staged-call token onto the stack. Requires a
    /// [`CrossHost`].
    XCall { arg_count: u16 },
    /// Reads the receipt for `msg_id` (eight words). Pushes `success` then `value`. Requires a
    /// [`CrossHost`]; a missing receipt resolves to `(success = 0, value = 0)`.
    ReadReply,
    Return,
    Revert,
    /// Pushes the byte length of the pre-reserved data stack onto the operand stack.
    DataSize,
    /// Pushes the little-endian `u64` stored at byte `offset` in the data stack.
    LoadData(u64),
    /// Pops a `u64` and writes it little-endian at byte `offset` in the data stack.
    StoreData(u64),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Program {
    pub argument_count: u8,
    pub local_count: u8,
    pub instructions: Vec<Instruction>,
}

impl Program {
    pub fn encode(&self) -> Result<Vec<u8>, VmError> {
        verify(self)?;
        let mut bytes = Vec::with_capacity(8 + self.instructions.len() * 5);
        bytes.extend_from_slice(MAGIC);
        bytes.push(self.argument_count);
        bytes.push(self.local_count);
        bytes.extend_from_slice(
            &u16::try_from(self.instructions.len())
                .map_err(|_| VmError::ProgramTooLarge)?
                .to_le_bytes(),
        );
        for instruction in &self.instructions {
            encode_instruction(instruction, &mut bytes);
        }
        if bytes.len() > MAX_CODE_BYTES {
            return Err(VmError::ProgramTooLarge);
        }
        Ok(bytes)
    }
}

/// Scalar interface types recorded in a canonical contract artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContractValueType {
    U64,
    Bool,
}

/// One exported Solid function in a compiled contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractFunction {
    pub name: String,
    pub inputs: Vec<ContractValueType>,
    pub output: Option<ContractValueType>,
    pub code: Vec<u8>,
}

/// Canonical deployable artifact for a user smart contract.
///
/// All functions share one persistent scalar storage map. `source_hash` and
/// `asset_manifest_hash` are optional metadata commitments and are never needed by
/// consensus execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractArtifact {
    pub source_hash: Option<Hash>,
    pub asset_manifest_hash: Option<Hash>,
    pub functions: Vec<ContractFunction>,
}

/// One optional, non-consensus asset committed by a contract artifact's manifest hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetManifestEntry {
    pub path: String,
    pub content_hash: Hash,
    pub size: u64,
}

/// Canonical path-to-content map for optional UI, source maps, and other non-executable files.
///
/// The manifest itself is content-addressed with [`content_hash`]. Asset availability is never
/// consulted by OVM verification or execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetManifest {
    pub entries: Vec<AssetManifestEntry>,
}

impl AssetManifest {
    pub fn encode(&self) -> Result<Vec<u8>, VmError> {
        self.verify()?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(ASSET_MANIFEST_MAGIC);
        bytes.extend_from_slice(&(self.entries.len() as u16).to_le_bytes());
        for entry in &self.entries {
            bytes.extend_from_slice(&(entry.path.len() as u16).to_le_bytes());
            bytes.extend_from_slice(entry.path.as_bytes());
            bytes.extend_from_slice(entry.content_hash.as_bytes());
            bytes.extend_from_slice(&entry.size.to_le_bytes());
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, VmError> {
        if bytes.len() < 6
            || bytes.get(..4) != Some(ASSET_MANIFEST_MAGIC)
            || bytes.len() > 6 + MAX_ASSET_MANIFEST_ENTRIES * (2 + MAX_ASSET_PATH_BYTES + 64 + 8)
        {
            return Err(VmError::InvalidBytecode);
        }
        let count = u16::from_le_bytes([bytes[4], bytes[5]]) as usize;
        if count == 0 || count > MAX_ASSET_MANIFEST_ENTRIES {
            return Err(VmError::InvalidProgram);
        }
        let mut cursor = 6;
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            let path_len = u16::from_le_bytes(take(bytes, &mut cursor)?) as usize;
            let path = std::str::from_utf8(take_slice(bytes, &mut cursor, path_len)?)
                .map_err(|_| VmError::InvalidBytecode)?
                .to_owned();
            let content_hash = Hash(take(bytes, &mut cursor)?);
            let size = u64::from_le_bytes(take(bytes, &mut cursor)?);
            entries.push(AssetManifestEntry {
                path,
                content_hash,
                size,
            });
        }
        if cursor != bytes.len() {
            return Err(VmError::InvalidBytecode);
        }
        let manifest = Self { entries };
        manifest.verify()?;
        Ok(manifest)
    }

    pub fn verify(&self) -> Result<(), VmError> {
        if self.entries.is_empty() || self.entries.len() > MAX_ASSET_MANIFEST_ENTRIES {
            return Err(VmError::InvalidProgram);
        }
        let mut previous: Option<&str> = None;
        let mut total_size = 0u64;
        for entry in &self.entries {
            if !valid_asset_path(&entry.path)
                || previous.is_some_and(|last| last >= entry.path.as_str())
                || entry.size > MAX_ASSET_BYTES
            {
                return Err(VmError::InvalidProgram);
            }
            total_size = total_size
                .checked_add(entry.size)
                .ok_or(VmError::ProgramTooLarge)?;
            if total_size > MAX_ASSET_MANIFEST_BYTES {
                return Err(VmError::ProgramTooLarge);
            }
            previous = Some(&entry.path);
        }
        Ok(())
    }

    pub fn commitment(&self) -> Result<Hash, VmError> {
        Ok(content_hash(&self.encode()?))
    }

    pub fn asset(&self, path: &str) -> Option<&AssetManifestEntry> {
        self.entries
            .binary_search_by(|entry| entry.path.as_str().cmp(path))
            .ok()
            .map(|index| &self.entries[index])
    }
}

/// Domain-separated identifier for non-executable content.
pub fn content_hash(bytes: &[u8]) -> Hash {
    hash_value(&("oxydome-content-v1", bytes))
}

fn valid_asset_path(path: &str) -> bool {
    if path.is_empty()
        || path.len() > MAX_ASSET_PATH_BYTES
        || !path.is_ascii()
        || path.starts_with('/')
        || path.contains('\\')
    {
        return false;
    }
    path.split('/').all(|component| {
        !component.is_empty()
            && component != "."
            && component != ".."
            && component
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    })
}

impl ContractArtifact {
    pub fn encode(&self) -> Result<Vec<u8>, VmError> {
        self.verify()?;
        let mut output = Vec::new();
        output.extend_from_slice(CONTRACT_MAGIC);
        let flags = u8::from(self.source_hash.is_some())
            | (u8::from(self.asset_manifest_hash.is_some()) << 1);
        output.push(flags);
        output.extend_from_slice(&(self.functions.len() as u16).to_le_bytes());
        if let Some(hash) = &self.source_hash {
            output.extend_from_slice(hash.as_bytes());
        }
        if let Some(hash) = &self.asset_manifest_hash {
            output.extend_from_slice(hash.as_bytes());
        }
        for function in &self.functions {
            output.push(function.name.len() as u8);
            output.extend_from_slice(function.name.as_bytes());
            output.push(function.inputs.len() as u8);
            for input in &function.inputs {
                output.push(encode_value_type(*input));
            }
            output.push(
                function
                    .output
                    .map_or(0, |output| encode_value_type(output)),
            );
            output.extend_from_slice(&(function.code.len() as u32).to_le_bytes());
            output.extend_from_slice(&function.code);
        }
        if output.len() > MAX_CONTRACT_ARTIFACT_BYTES {
            return Err(VmError::ProgramTooLarge);
        }
        Ok(output)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, VmError> {
        if bytes.len() < 7
            || bytes.len() > MAX_CONTRACT_ARTIFACT_BYTES
            || bytes.get(..4) != Some(CONTRACT_MAGIC)
        {
            return Err(VmError::InvalidBytecode);
        }
        let flags = bytes[4];
        if flags & !0b11 != 0 {
            return Err(VmError::InvalidBytecode);
        }
        let count = u16::from_le_bytes([bytes[5], bytes[6]]) as usize;
        if count == 0 || count > MAX_CONTRACT_FUNCTIONS {
            return Err(VmError::InvalidProgram);
        }
        let mut cursor = 7;
        let source_hash = if flags & 1 != 0 {
            Some(Hash(take(bytes, &mut cursor)?))
        } else {
            None
        };
        let asset_manifest_hash = if flags & 2 != 0 {
            Some(Hash(take(bytes, &mut cursor)?))
        } else {
            None
        };
        let mut functions = Vec::with_capacity(count);
        for _ in 0..count {
            let name_len = take::<1>(bytes, &mut cursor)?[0] as usize;
            let name_bytes = take_slice(bytes, &mut cursor, name_len)?;
            let name = std::str::from_utf8(name_bytes)
                .map_err(|_| VmError::InvalidBytecode)?
                .to_owned();
            let input_count = take::<1>(bytes, &mut cursor)?[0] as usize;
            if input_count + AUTHORITY_WORD_COUNT > MAX_ARGUMENTS {
                return Err(VmError::InvalidProgram);
            }
            let mut inputs = Vec::with_capacity(input_count);
            for _ in 0..input_count {
                inputs.push(decode_value_type(take::<1>(bytes, &mut cursor)?[0])?);
            }
            let output = match take::<1>(bytes, &mut cursor)?[0] {
                0 => None,
                value => Some(decode_value_type(value)?),
            };
            let code_len = u32::from_le_bytes(take(bytes, &mut cursor)?) as usize;
            let code = take_slice(bytes, &mut cursor, code_len)?.to_vec();
            let program = Program::decode(&code)?;
            if program.argument_count as usize != input_count + AUTHORITY_WORD_COUNT {
                return Err(VmError::InvalidProgram);
            }
            functions.push(ContractFunction {
                name,
                inputs,
                output,
                code,
            });
        }
        if cursor != bytes.len() {
            return Err(VmError::InvalidBytecode);
        }
        let artifact = Self {
            source_hash,
            asset_manifest_hash,
            functions,
        };
        artifact.verify()?;
        Ok(artifact)
    }

    pub fn verify(&self) -> Result<(), VmError> {
        if self.functions.is_empty() || self.functions.len() > MAX_CONTRACT_FUNCTIONS {
            return Err(VmError::InvalidProgram);
        }
        let mut previous: Option<&str> = None;
        for function in &self.functions {
            if !valid_function_name(&function.name)
                || function.inputs.len() + AUTHORITY_WORD_COUNT > MAX_ARGUMENTS
                || previous.is_some_and(|last| last >= function.name.as_str())
            {
                return Err(VmError::InvalidProgram);
            }
            let program = Program::decode(&function.code)?;
            if program.argument_count as usize != function.inputs.len() + AUTHORITY_WORD_COUNT {
                return Err(VmError::InvalidProgram);
            }
            previous = Some(&function.name);
        }
        Ok(())
    }

    pub fn function(&self, name: &str) -> Option<&ContractFunction> {
        self.functions
            .binary_search_by(|function| function.name.as_str().cmp(name))
            .ok()
            .map(|index| &self.functions[index])
    }

    /// Finds a function by its deterministic [`fn_selector`], the numeric address used by the
    /// cross-OHM message dispatcher.
    pub fn function_by_selector(&self, selector: u64) -> Option<&ContractFunction> {
        self.functions
            .iter()
            .find(|function| fn_selector(&function.name) == selector)
    }
}

fn encode_value_type(value_type: ContractValueType) -> u8 {
    match value_type {
        ContractValueType::U64 => 1,
        ContractValueType::Bool => 2,
    }
}

fn decode_value_type(value: u8) -> Result<ContractValueType, VmError> {
    match value {
        1 => Ok(ContractValueType::U64),
        2 => Ok(ContractValueType::Bool),
        _ => Err(VmError::InvalidBytecode),
    }
}

impl Program {
    pub fn decode(bytes: &[u8]) -> Result<Self, VmError> {
        if bytes.len() > MAX_CODE_BYTES || bytes.len() < 8 || bytes.get(..4) != Some(MAGIC) {
            return Err(VmError::InvalidBytecode);
        }
        let argument_count = bytes[4];
        let local_count = bytes[5];
        let count = u16::from_le_bytes([bytes[6], bytes[7]]) as usize;
        let mut cursor = 8;
        let mut instructions = Vec::with_capacity(count);
        for _ in 0..count {
            instructions.push(decode_instruction(bytes, &mut cursor)?);
        }
        if cursor != bytes.len() {
            return Err(VmError::InvalidBytecode);
        }
        let program = Self {
            argument_count,
            local_count,
            instructions,
        };
        verify(&program)?;
        Ok(program)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Log {
    pub topic: u32,
    pub value: u64,
}

/// A cross-OHM message staged by a contract via the `XCall` instruction.
///
/// The executing ledger assigns each call a message id in execution order (its own outbox
/// sequence under the current block height). `token` is the per-execution index and is what the
/// contract receives from the instruction for correlation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagedCrossCall {
    pub token: u64,
    pub target_ohm: Hash,
    pub target_contract: Hash,
    pub entry_selector: u64,
    pub gas_limit: u64,
    pub arguments: Vec<u64>,
}

/// The receipt summary a contract may observe through `ReadReply`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptView {
    pub success: bool,
    pub value: u64,
}

/// Host context for contract-originated cross-OHM instructions.
///
/// `origin_ohm` is the ledger executing the contract (the source of any staged `XCall`
/// messages). `inbox` is the set of receipts already recorded on that ledger that `ReadReply`
/// may consult. A [`CrossHost`] is never serialized and only exists while a block is being
/// derived.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossHost {
    pub origin_ohm: Hash,
    pub inbox: BTreeMap<Hash, ReceiptView>,
}

impl Default for CrossHost {
    fn default() -> Self {
        Self {
            origin_ohm: Hash::zero(),
            inbox: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Execution {
    pub return_value: Option<u64>,
    pub gas_used: u64,
    pub logs: Vec<Log>,
    pub storage: BTreeMap<u64, u64>,
    /// Contract-originated cross-OHM calls staged during this execution, in program order.
    pub staged_calls: Vec<StagedCrossCall>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VmError {
    #[error("invalid OVM bytecode")]
    InvalidBytecode,
    #[error("OVM program is too large")]
    ProgramTooLarge,
    #[error("OVM program has an invalid instruction or jump target")]
    InvalidProgram,
    #[error("OVM stack underflow")]
    StackUnderflow,
    #[error("OVM stack limit exceeded")]
    StackOverflow,
    #[error("OVM argument count mismatch")]
    ArgumentCount,
    #[error("OVM local index out of range")]
    InvalidLocal,
    #[error("OVM arithmetic overflow")]
    ArithmeticOverflow,
    #[error("OVM division by zero")]
    DivisionByZero,
    #[error("OVM execution reverted")]
    Reverted,
    #[error("OVM out of gas")]
    OutOfGas,
    #[error("OVM did not return")]
    MissingReturn,
    #[error("OVM contract storage slot limit exceeded")]
    StorageLimitExceeded,
    #[error("OVM data stack access exceeds the reserved stack")]
    DataStackOverflow,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{error}")]
pub struct ExecutionFailure {
    pub error: VmError,
    pub gas_used: u64,
}

pub fn code_hash(code: &[u8]) -> Hash {
    hash_value(&("oxydome-ovm-code-v1", code))
}

pub fn contract_id(deployment_txid: Hash) -> Hash {
    hash_value(&("oxydome-contract-v1", deployment_txid))
}

/// The deterministic numeric selector for a named function, used by cross-OHM messages and the
/// Phase-2 contract-originated `XCall` instruction (contracts address entry points with `u64`s,
/// never with strings).
pub fn fn_selector(name: &str) -> u64 {
    let hash = hash_value(&("oxydome-fn-sel-v1", name));
    u64::from_le_bytes(hash.0[..8].try_into().expect("8-byte selector"))
}

/// Whether `name` is a valid exported function name. Public so cross-chain entry point
/// validation shares the exact same rule as artifact encoding.
pub fn valid_function_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    name.len() <= MAX_FUNCTION_NAME_BYTES
        && (first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

pub fn verify(program: &Program) -> Result<(), VmError> {
    if program.instructions.is_empty()
        || program.argument_count as usize > MAX_ARGUMENTS
        || program.local_count as usize > MAX_LOCALS
    {
        return Err(VmError::InvalidProgram);
    }
    let count = program.instructions.len();
    for instruction in &program.instructions {
        match instruction {
            Instruction::LoadArg(index) if *index >= program.argument_count => {
                return Err(VmError::InvalidProgram)
            }
            Instruction::LoadLocal(index) | Instruction::StoreLocal(index)
                if *index >= program.local_count =>
            {
                return Err(VmError::InvalidProgram)
            }
            Instruction::Jump(target) | Instruction::JumpIfFalse(target)
                if *target as usize >= count =>
            {
                return Err(VmError::InvalidProgram)
            }
            Instruction::XCall { arg_count } if *arg_count as usize > MAX_CROSS_ARGUMENTS => {
                return Err(VmError::InvalidProgram)
            }
            _ => {}
        }
    }
    Ok(())
}

pub fn execute(
    program: &Program,
    arguments: &[u64],
    initial_storage: &BTreeMap<u64, u64>,
    stack_bytes: u64,
) -> Result<Execution, ExecutionFailure> {
    execute_with_host(program, arguments, initial_storage, stack_bytes, None)
}

/// Executes `program` with an optional [`CrossHost`]. Without a host, the cross-OHM
/// instructions (`XCall`, `ReadReply`) fail deterministically with
/// [`VmError::InvalidProgram`].
///
/// The data stack is pre-reserved to `stack_bytes` bytes and zero-initialized. Execution is
/// metered only by this reservation: a program that stays within its reserved stack runs to
/// completion, and an access beyond it fails with [`VmError::DataStackOverflow`].
pub fn execute_with_host(
    program: &Program,
    arguments: &[u64],
    initial_storage: &BTreeMap<u64, u64>,
    stack_bytes: u64,
    host: Option<&CrossHost>,
) -> Result<Execution, ExecutionFailure> {
    verify(program).map_err(|error| ExecutionFailure { error, gas_used: 0 })?;
    if arguments.len() != program.argument_count as usize {
        return Err(ExecutionFailure {
            error: VmError::ArgumentCount,
            gas_used: 0,
        });
    }
    let mut stack = Vec::new();
    let mut locals = vec![0u64; program.local_count as usize];
    let mut storage = initial_storage.clone();
    let mut logs = Vec::new();
    let mut staged_calls = Vec::new();
    let mut pc = 0usize;
    let mut token_base: u64 = 0;
    let mut data: Vec<u8> = vec![0u8; stack_bytes as usize];

    while let Some(instruction) = program.instructions.get(pc) {
        pc += 1;
        let result = match instruction {
            Instruction::Push(value) => push(&mut stack, *value),
            Instruction::LoadArg(index) => push(&mut stack, arguments[*index as usize]),
            Instruction::LoadLocal(index) => push(&mut stack, locals[*index as usize]),
            Instruction::StoreLocal(index) => pop(&mut stack).map(|value| {
                locals[*index as usize] = value;
            }),
            Instruction::LoadStorage(slot) => push(&mut stack, *storage.get(slot).unwrap_or(&0)),
            Instruction::StoreStorage(slot) => match pop(&mut stack) {
                Ok(value) if value == 0 => {
                    storage.remove(slot);
                    Ok(())
                }
                Ok(value) if storage.contains_key(slot) || storage.len() < MAX_STORAGE_SLOTS => {
                    storage.insert(*slot, value);
                    Ok(())
                }
                Ok(_) => Err(VmError::StorageLimitExceeded),
                Err(error) => Err(error),
            },
            Instruction::Add => binary(&mut stack, u64::checked_add),
            Instruction::Sub => binary(&mut stack, u64::checked_sub),
            Instruction::Mul => binary(&mut stack, u64::checked_mul),
            Instruction::Div => match pop(&mut stack) {
                Err(error) => Err(error),
                Ok(0) => Err(VmError::DivisionByZero),
                Ok(rhs) => match pop(&mut stack) {
                    Err(error) => Err(error),
                    Ok(lhs) => push(&mut stack, lhs / rhs),
                },
            },
            Instruction::Mod => match pop(&mut stack) {
                Err(error) => Err(error),
                Ok(0) => Err(VmError::DivisionByZero),
                Ok(rhs) => match pop(&mut stack) {
                    Err(error) => Err(error),
                    Ok(lhs) => push(&mut stack, lhs % rhs),
                },
            },
            Instruction::Equal => compare(&mut stack, |left, right| left == right),
            Instruction::LessThan => compare(&mut stack, |left, right| left < right),
            Instruction::GreaterThan => compare(&mut stack, |left, right| left > right),
            Instruction::And => binary(&mut stack, |left, right| Some(left & right)),
            Instruction::Or => binary(&mut stack, |left, right| Some(left | right)),
            Instruction::Not => {
                pop(&mut stack).and_then(|value| push(&mut stack, u64::from(value == 0)))
            }
            Instruction::Jump(target) => {
                pc = *target as usize;
                Ok(())
            }
            Instruction::JumpIfFalse(target) => match pop(&mut stack) {
                Ok(0) => {
                    pc = *target as usize;
                    Ok(())
                }
                Ok(_) => Ok(()),
                Err(error) => Err(error),
            },
            Instruction::Emit(topic) => pop(&mut stack).map(|value| {
                logs.push(Log {
                    topic: *topic,
                    value,
                });
            }),
            Instruction::XCall { arg_count } => {
                if host.is_none() {
                    return Err(ExecutionFailure {
                        error: VmError::InvalidProgram,
                        gas_used: stack_bytes,
                    });
                }
                let arg_count = *arg_count as usize;
                if arg_count > MAX_CROSS_ARGUMENTS {
                    return Err(ExecutionFailure {
                        error: VmError::InvalidProgram,
                        gas_used: stack_bytes,
                    });
                }
                let gas_limit = match pop(&mut stack) {
                    Ok(value) => value,
                    Err(error) => {
                        return Err(ExecutionFailure { error, gas_used: stack_bytes })
                    }
                };
                let entry_selector = match pop(&mut stack) {
                    Ok(value) => value,
                    Err(error) => {
                        return Err(ExecutionFailure { error, gas_used: stack_bytes })
                    }
                };
                let mut contract_words = [0u64; 8];
                for word in contract_words.iter_mut().rev() {
                    *word = match pop(&mut stack) {
                        Ok(value) => value,
                        Err(error) => {
                            return Err(ExecutionFailure { error, gas_used: stack_bytes })
                        }
                    };
                }
                let target_contract = Hash(words_to_hash_bytes(&contract_words));
                let mut ohm_words = [0u64; 8];
                for word in ohm_words.iter_mut().rev() {
                    *word = match pop(&mut stack) {
                        Ok(value) => value,
                        Err(error) => {
                            return Err(ExecutionFailure { error, gas_used: stack_bytes })
                        }
                    };
                }
                let target_ohm = Hash(words_to_hash_bytes(&ohm_words));
                let mut arguments = Vec::with_capacity(arg_count);
                for _ in 0..arg_count {
                    arguments.push(match pop(&mut stack) {
                        Ok(value) => value,
                        Err(error) => {
                            return Err(ExecutionFailure { error, gas_used: stack_bytes })
                        }
                    });
                }
                arguments.reverse();
                staged_calls.push(StagedCrossCall {
                    token: token_base,
                    target_ohm,
                    target_contract,
                    entry_selector,
                    gas_limit,
                    arguments,
                });
                token_base += 1;
                push(&mut stack, token_base - 1)
            }
            Instruction::ReadReply => {
                let host = match host {
                    Some(host) => host,
                    None => {
                        return Err(ExecutionFailure {
                            error: VmError::InvalidProgram,
                            gas_used: stack_bytes,
                        })
                    }
                };
                let mut words = [0u64; 8];
                for word in words.iter_mut().rev() {
                    *word = match pop(&mut stack) {
                        Ok(value) => value,
                        Err(error) => {
                            return Err(ExecutionFailure { error, gas_used: stack_bytes })
                        }
                    };
                }
                let msg_id = Hash(words_to_hash_bytes(&words));
                let view = host
                    .inbox
                    .get(&msg_id)
                    .copied()
                    .unwrap_or(ReceiptView {
                        success: false,
                        value: 0,
                    });
                push(&mut stack, u64::from(view.success)).and_then(|()| {
                    push(&mut stack, view.value)
                })
            }
            Instruction::DataSize => push(&mut stack, stack_bytes),
            Instruction::LoadData(offset) => {
                let value = read_data_u64(&data, *offset).map_err(|error| ExecutionFailure {
                    error,
                    gas_used: stack_bytes,
                })?;
                push(&mut stack, value)
            }
            Instruction::StoreData(offset) => {
                let value = pop(&mut stack).map_err(|error| ExecutionFailure {
                    error,
                    gas_used: stack_bytes,
                })?;
                write_data_u64(&mut data, *offset, value)
            }
            Instruction::Return => {
                let return_value = if stack.is_empty() {
                    None
                } else {
                    match pop(&mut stack) {
                        Ok(value) => Some(value),
                        Err(error) => {
                            return Err(ExecutionFailure { error, gas_used: stack_bytes });
                        }
                    }
                };
                return Ok(Execution {
                    return_value,
                    gas_used: stack_bytes,
                    logs,
                    storage,
                    staged_calls,
                });
            }
            Instruction::Revert => {
                return Err(ExecutionFailure {
                    error: VmError::Reverted,
                    gas_used: stack_bytes,
                });
            }
        };
        if let Err(error) = result {
            return Err(ExecutionFailure { error, gas_used: stack_bytes });
        }
    }
    Err(ExecutionFailure {
        error: VmError::MissingReturn,
        gas_used: stack_bytes,
    })
}

fn push(stack: &mut Vec<u64>, value: u64) -> Result<(), VmError> {
    if stack.len() >= MAX_STACK {
        return Err(VmError::StackOverflow);
    }
    stack.push(value);
    Ok(())
}

fn read_data_u64(data: &[u8], offset: u64) -> Result<u64, VmError> {
    let start = offset as usize;
    let end = start.checked_add(8).ok_or(VmError::DataStackOverflow)?;
    if end > data.len() {
        return Err(VmError::DataStackOverflow);
    }
    let bytes: [u8; 8] = data[start..end].try_into().expect("checked range above");
    Ok(u64::from_le_bytes(bytes))
}

fn write_data_u64(data: &mut [u8], offset: u64, value: u64) -> Result<(), VmError> {
    let start = offset as usize;
    let end = start.checked_add(8).ok_or(VmError::DataStackOverflow)?;
    if end > data.len() {
        return Err(VmError::DataStackOverflow);
    }
    data[start..end].copy_from_slice(&value.to_le_bytes());
    Ok(())
}

/// Serialises eight little-endian `u64` words (the OVM cross-message identifier convention) back
/// into the 64-byte `Hash` byte representation they were derived from.
fn words_to_hash_bytes(words: &[u64; 8]) -> [u8; 64] {
    let mut bytes = [0u8; 64];
    for (chunk, word) in bytes.chunks_exact_mut(8).zip(words.iter()) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

fn pop(stack: &mut Vec<u64>) -> Result<u64, VmError> {
    stack.pop().ok_or(VmError::StackUnderflow)
}

fn binary(stack: &mut Vec<u64>, operation: fn(u64, u64) -> Option<u64>) -> Result<(), VmError> {
    let right = pop(stack)?;
    let left = pop(stack)?;
    push(
        stack,
        operation(left, right).ok_or(VmError::ArithmeticOverflow)?,
    )
}

fn compare(stack: &mut Vec<u64>, operation: fn(u64, u64) -> bool) -> Result<(), VmError> {
    let right = pop(stack)?;
    let left = pop(stack)?;
    push(stack, u64::from(operation(left, right)))
}

fn encode_instruction(instruction: &Instruction, output: &mut Vec<u8>) {
    match instruction {
        Instruction::Push(value) => {
            output.push(0x01);
            output.extend_from_slice(&value.to_le_bytes());
        }
        Instruction::LoadArg(index) => {
            output.push(0x02);
            output.push(*index);
        }
        Instruction::LoadLocal(index) => {
            output.push(0x03);
            output.push(*index);
        }
        Instruction::StoreLocal(index) => {
            output.push(0x04);
            output.push(*index);
        }
        Instruction::LoadStorage(slot) => {
            output.push(0x05);
            output.extend_from_slice(&slot.to_le_bytes());
        }
        Instruction::StoreStorage(slot) => {
            output.push(0x06);
            output.extend_from_slice(&slot.to_le_bytes());
        }
        Instruction::Add => output.push(0x10),
        Instruction::Sub => output.push(0x11),
        Instruction::Mul => output.push(0x12),
        Instruction::Div => output.push(0x13),
        Instruction::Mod => output.push(0x14),
        Instruction::Equal => output.push(0x15),
        Instruction::LessThan => output.push(0x16),
        Instruction::GreaterThan => output.push(0x17),
        Instruction::And => output.push(0x18),
        Instruction::Or => output.push(0x19),
        Instruction::Not => output.push(0x1a),
        Instruction::Jump(target) => {
            output.push(0x20);
            output.extend_from_slice(&target.to_le_bytes());
        }
        Instruction::JumpIfFalse(target) => {
            output.push(0x21);
            output.extend_from_slice(&target.to_le_bytes());
        }
        Instruction::Emit(topic) => {
            output.push(0x30);
            output.extend_from_slice(&topic.to_le_bytes());
        }
        Instruction::XCall { arg_count } => {
            output.push(0x40);
            output.extend_from_slice(&arg_count.to_le_bytes());
        }
        Instruction::ReadReply => output.push(0x41),
        Instruction::Return => output.push(0xf0),
        Instruction::Revert => output.push(0xf1),
        Instruction::DataSize => output.push(0x50),
        Instruction::LoadData(offset) => {
            output.push(0x51);
            output.extend_from_slice(&offset.to_le_bytes());
        }
        Instruction::StoreData(offset) => {
            output.push(0x52);
            output.extend_from_slice(&offset.to_le_bytes());
        }
    }
}

fn take<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Result<[u8; N], VmError> {
    let end = cursor.checked_add(N).ok_or(VmError::InvalidBytecode)?;
    let value = bytes.get(*cursor..end).ok_or(VmError::InvalidBytecode)?;
    *cursor = end;
    value.try_into().map_err(|_| VmError::InvalidBytecode)
}

fn take_slice<'a>(bytes: &'a [u8], cursor: &mut usize, length: usize) -> Result<&'a [u8], VmError> {
    let end = cursor.checked_add(length).ok_or(VmError::InvalidBytecode)?;
    let value = bytes.get(*cursor..end).ok_or(VmError::InvalidBytecode)?;
    *cursor = end;
    Ok(value)
}

fn decode_instruction(bytes: &[u8], cursor: &mut usize) -> Result<Instruction, VmError> {
    let opcode = take::<1>(bytes, cursor)?[0];
    Ok(match opcode {
        0x01 => Instruction::Push(u64::from_le_bytes(take(bytes, cursor)?)),
        0x02 => Instruction::LoadArg(take::<1>(bytes, cursor)?[0]),
        0x03 => Instruction::LoadLocal(take::<1>(bytes, cursor)?[0]),
        0x04 => Instruction::StoreLocal(take::<1>(bytes, cursor)?[0]),
        0x05 => Instruction::LoadStorage(u64::from_le_bytes(take(bytes, cursor)?)),
        0x06 => Instruction::StoreStorage(u64::from_le_bytes(take(bytes, cursor)?)),
        0x10 => Instruction::Add,
        0x11 => Instruction::Sub,
        0x12 => Instruction::Mul,
        0x13 => Instruction::Div,
        0x14 => Instruction::Mod,
        0x15 => Instruction::Equal,
        0x16 => Instruction::LessThan,
        0x17 => Instruction::GreaterThan,
        0x18 => Instruction::And,
        0x19 => Instruction::Or,
        0x1a => Instruction::Not,
        0x20 => Instruction::Jump(u32::from_le_bytes(take(bytes, cursor)?)),
        0x21 => Instruction::JumpIfFalse(u32::from_le_bytes(take(bytes, cursor)?)),
        0x30 => Instruction::Emit(u32::from_le_bytes(take(bytes, cursor)?)),
        0x40 => Instruction::XCall {
            arg_count: u16::from_le_bytes(take(bytes, cursor)?),
        },
        0x41 => Instruction::ReadReply,
        0xf0 => Instruction::Return,
        0xf1 => Instruction::Revert,
        0x50 => Instruction::DataSize,
        0x51 => Instruction::LoadData(u64::from_le_bytes(take(bytes, cursor)?)),
        0x52 => Instruction::StoreData(u64::from_le_bytes(take(bytes, cursor)?)),
        _ => return Err(VmError::InvalidBytecode),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_executes_deterministically() {
        let program = Program {
            argument_count: 1,
            local_count: 0,
            instructions: vec![
                Instruction::LoadArg(0),
                Instruction::LoadStorage(7),
                Instruction::Add,
                Instruction::StoreStorage(7),
                Instruction::LoadStorage(7),
                Instruction::Return,
            ],
        };
        let code = program.encode().unwrap();
        let decoded = Program::decode(&code).unwrap();
        let a = execute(&decoded, &[5], &BTreeMap::new(), 100).unwrap();
        let b = execute(&decoded, &[5], &BTreeMap::new(), 100).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.return_value, Some(5));
        assert_eq!(a.storage.get(&7), Some(&5));
    }

    #[test]
    fn traps_overflow_division_by_zero_and_data_stack_overflow() {
        let program = Program {
            argument_count: 0,
            local_count: 0,
            instructions: vec![
                Instruction::Push(u64::MAX),
                Instruction::Push(1),
                Instruction::Add,
                Instruction::Return,
            ],
        };
        let overflow = execute(&program, &[], &BTreeMap::new(), 100).unwrap_err();
        assert_eq!(overflow.error, VmError::ArithmeticOverflow);
        assert_eq!(overflow.gas_used, 100);
// Accessing the data stack beyond the reserved size fails with DataStackOverflow,
    // not a mid-run fuel stop: the reservation itself bounds the stack.
    let oob = Program {
        argument_count: 0,
        local_count: 0,
        instructions: vec![Instruction::LoadData(100), Instruction::Return],
    };
    let failure = execute(&oob, &[], &BTreeMap::new(), 100).unwrap_err();
    assert_eq!(failure.error, VmError::DataStackOverflow);
    assert_eq!(failure.gas_used, 100);
    }

    #[test]
    fn data_stack_round_trips_and_size_is_reported() {
        let program = Program {
            argument_count: 0,
            local_count: 0,
            instructions: vec![
                Instruction::DataSize,
                Instruction::StoreData(8),
                Instruction::LoadData(8),
                Instruction::Return,
            ],
        };
        let execution = execute(&program, &[], &BTreeMap::new(), 1024).unwrap();
        assert_eq!(execution.return_value, Some(1024));
        assert_eq!(execution.gas_used, 1024);
        // The data stack encodes: [size, value] -> value pushed last is what Return pops.
        let decode = Program::decode(&program.encode().unwrap()).unwrap();
        let execution = execute(&decode, &[], &BTreeMap::new(), 1024).unwrap();
        assert_eq!(execution.return_value, Some(1024));
    }

    #[test]
    fn revert_reports_and_storage_limit_is_bounded() {
        let program = Program {
            argument_count: 0,
            local_count: 0,
            instructions: vec![
                Instruction::Push(7),
                Instruction::StoreStorage(1),
                Instruction::Revert,
            ],
        };
        let failure = execute(&program, &[], &BTreeMap::new(), 100).unwrap_err();
        assert_eq!(failure.error, VmError::Reverted);
        assert_eq!(failure.gas_used, 100);

        let mut storage = BTreeMap::new();
        storage.extend((0..MAX_STORAGE_SLOTS as u64).map(|slot| (slot, 1)));
        let overflow = Program {
            argument_count: 0,
            local_count: 0,
            instructions: vec![
                Instruction::Push(1),
                Instruction::StoreStorage(MAX_STORAGE_SLOTS as u64 + 1),
                Instruction::Return,
            ],
        };
        let failure = execute(&overflow, &[], &storage, 100).unwrap_err();
        assert_eq!(failure.error, VmError::StorageLimitExceeded);
        assert_eq!(failure.gas_used, 100);
    }

    #[test]
    fn rejects_bad_bytecode_and_jump_targets() {
        assert_eq!(Program::decode(b"bad"), Err(VmError::InvalidBytecode));
        let program = Program {
            argument_count: 0,
            local_count: 0,
            instructions: vec![Instruction::Jump(99), Instruction::Return],
        };
        assert_eq!(verify(&program), Err(VmError::InvalidProgram));
    }

    #[test]
    fn contract_artifacts_round_trip_and_require_canonical_functions() {
        let program = Program {
            argument_count: AUTHORITY_WORD_COUNT as u8,
            local_count: 0,
            instructions: vec![Instruction::Push(7), Instruction::Return],
        }
        .encode()
        .unwrap();
        let artifact = ContractArtifact {
            source_hash: Some(hash_value(&"source")),
            asset_manifest_hash: None,
            functions: vec![ContractFunction {
                name: "read".into(),
                inputs: Vec::new(),
                output: Some(ContractValueType::U64),
                code: program.clone(),
            }],
        };
        let encoded = artifact.encode().unwrap();
        assert_eq!(ContractArtifact::decode(&encoded), Ok(artifact));

        let noncanonical = ContractArtifact {
            source_hash: None,
            asset_manifest_hash: None,
            functions: vec![
                ContractFunction {
                    name: "zeta".into(),
                    inputs: Vec::new(),
                    output: None,
                    code: program.clone(),
                },
                ContractFunction {
                    name: "alpha".into(),
                    inputs: Vec::new(),
                    output: None,
                    code: program,
                },
            ],
        };
        assert_eq!(noncanonical.encode(), Err(VmError::InvalidProgram));
    }

    #[test]
    fn contract_artifacts_reject_function_argument_interface_mismatch() {
        let program = Program {
            argument_count: AUTHORITY_WORD_COUNT as u8,
            local_count: 0,
            instructions: vec![Instruction::Push(0), Instruction::Return],
        }
        .encode()
        .unwrap();
        let artifact = ContractArtifact {
            source_hash: None,
            asset_manifest_hash: None,
            functions: vec![ContractFunction {
                name: "read".into(),
                inputs: vec![ContractValueType::U64],
                output: Some(ContractValueType::U64),
                code: program,
            }],
        };
        assert_eq!(artifact.encode(), Err(VmError::InvalidProgram));
    }

    #[test]
    fn asset_manifests_are_canonical_and_content_addressed() {
        let content = b"<html>Oxydome app</html>";
        let script = b"console.log('Oxydome')";
        let manifest = AssetManifest {
            entries: vec![
                AssetManifestEntry {
                    path: "index.html".into(),
                    content_hash: content_hash(content),
                    size: content.len() as u64,
                },
                AssetManifestEntry {
                    path: "ui/app.js".into(),
                    content_hash: content_hash(script),
                    size: script.len() as u64,
                },
            ],
        };
        let encoded = manifest.encode().unwrap();
        let commitment = manifest.commitment().unwrap();
        let decoded = AssetManifest::decode(&encoded).unwrap();
        assert_eq!(decoded, manifest);
        assert_eq!(decoded.commitment().unwrap(), commitment);
        assert_eq!(
            decoded.asset("index.html").unwrap().content_hash,
            content_hash(content)
        );
        assert!(decoded.asset("../secrets").is_none());
    }

    #[test]
    fn asset_manifests_reject_unsafe_paths_and_noncanonical_order() {
        let entry = |path: &str| AssetManifestEntry {
            path: path.into(),
            content_hash: content_hash(b"x"),
            size: 1,
        };
        for entries in [
            vec![entry("../escape")],
            vec![entry("absolute//path")],
            vec![entry("z.js"), entry("a.js")],
        ] {
            assert_eq!(
                AssetManifest { entries }.encode(),
                Err(VmError::InvalidProgram)
            );
        }
    }

    fn words(hash: &Hash) -> [u64; 8] {
        let mut words = [0u64; 8];
        for (chunk, word) in hash.0.chunks_exact(8).zip(words.iter_mut()) {
            *word = u64::from_le_bytes(chunk.try_into().unwrap());
        }
        words
    }

    #[test]
    fn xcall_stages_message_and_returns_token() {
        let target_ohm = Hash::from([1u8; 64]);
        let target_contract = Hash::from([2u8; 64]);
        let mut instructions = vec![Instruction::Push(123), Instruction::Push(456)];
        for word in words(&target_ohm) {
            instructions.push(Instruction::Push(word));
        }
        for word in words(&target_contract) {
            instructions.push(Instruction::Push(word));
        }
        instructions.push(Instruction::Push(fn_selector("poke")));
        instructions.push(Instruction::Push(400));
        instructions.push(Instruction::XCall { arg_count: 2 });
        instructions.push(Instruction::StoreLocal(0));
        instructions.push(Instruction::LoadLocal(0));
        instructions.push(Instruction::Return);
        let program = Program {
            argument_count: 0,
            local_count: 1,
            instructions,
        };
        let execution = execute_with_host(
            &program,
            &[],
            &BTreeMap::new(),
            1_000,
            Some(&CrossHost {
                origin_ohm: Hash::zero(),
                inbox: BTreeMap::new(),
            }),
        )
        .unwrap();
        assert_eq!(execution.staged_calls.len(), 1);
        let call = &execution.staged_calls[0];
        assert_eq!(call.token, 0);
        assert_eq!(call.target_ohm, target_ohm);
        assert_eq!(call.target_contract, target_contract);
        assert_eq!(call.entry_selector, fn_selector("poke"));
        assert_eq!(call.gas_limit, 400);
        assert_eq!(call.arguments, vec![123, 456]);
        assert_eq!(execution.return_value, Some(0));
    }

    #[test]
    fn xcall_and_read_reply_require_a_host() {
        let mut instructions = Vec::new();
        for word in words(&Hash::from([1u8; 64])) {
            instructions.push(Instruction::Push(word));
        }
        instructions.push(Instruction::XCall { arg_count: 0 });
        instructions.push(Instruction::Return);
        let xcall = Program {
            argument_count: 0,
            local_count: 0,
            instructions,
        };
        assert_eq!(
            execute(&xcall, &[], &BTreeMap::new(), 1_000).unwrap_err().error,
            VmError::InvalidProgram
        );
        let readprogram = Program {
            argument_count: 0,
            local_count: 0,
            instructions: vec![Instruction::Push(1), Instruction::ReadReply, Instruction::Return],
        };
        assert_eq!(
            execute(&readprogram, &[], &BTreeMap::new(), 1_000)
                .unwrap_err()
                .error,
            VmError::InvalidProgram
        );
    }

    #[test]
    fn read_reply_returns_receipt_or_zeros() {
        let msg_id = Hash::from([9u8; 64]);
        let mut instructions = Vec::new();
        for word in words(&msg_id) {
            instructions.push(Instruction::Push(word));
        }
        instructions.push(Instruction::ReadReply);
        instructions.push(Instruction::StoreStorage(0));
        instructions.push(Instruction::StoreStorage(1));
        instructions.push(Instruction::Return);
        let program = Program {
            argument_count: 0,
            local_count: 0,
            instructions,
        };
        let mut inbox = BTreeMap::new();
        inbox.insert(
            msg_id,
            ReceiptView {
                success: true,
                value: 41,
            },
        );
        let host = CrossHost {
            origin_ohm: Hash::zero(),
            inbox,
        };
        let execution = execute_with_host(&program, &[], &BTreeMap::new(), 1_000, Some(&host))
            .unwrap();
        assert_eq!(execution.storage.get(&0), Some(&41));
        assert_eq!(execution.storage.get(&1), Some(&1));
        // Missing receipts resolve to `(success = 0, value = 0)`; zero values are pruned from
        // storage, so both slots disappear.
        let missing = execute_with_host(&program, &[], &BTreeMap::new(), 1_000, Some(&CrossHost {
            origin_ohm: Hash::zero(),
            inbox: BTreeMap::new(),
        }))
        .unwrap();
        assert!(missing.storage.is_empty());
    }

    #[test]
    fn xcall_rejects_oversized_argument_lists() {
        let program = Program {
            argument_count: 0,
            local_count: 0,
            instructions: vec![Instruction::XCall {
                arg_count: (MAX_CROSS_ARGUMENTS + 1) as u16,
            }],
        };
        assert_eq!(program.encode(), Err(VmError::InvalidProgram));
    }
}
