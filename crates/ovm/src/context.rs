//! Execution context for OVM opcode handlers.

use crate::{CrossHost, Log, StagedCrossCall, VmError, MAX_STACK};
use oxydome_crypto::Hash;
use std::collections::BTreeMap;

/// Execution context passed to every opcode handler.
///
/// Holds the operand stack, locals, storage, data stack, cross-host context,
/// and gas bookkeeping. Handlers read from and mutate this struct.
pub(crate) struct ExecutionContext<'a> {
    pub stack: Vec<u64>,
    pub locals: Vec<u64>,
    pub storage: BTreeMap<u64, u64>,
    pub data: Vec<u8>,
    pub arguments: &'a [u64],
    pub logs: Vec<Log>,
    pub staged_calls: Vec<StagedCrossCall>,

    /// Program counter — index into `Program.instructions`.
    pub pc: usize,
    /// Number of instructions executed so far.
    pub instructions_used: u64,
    /// Gas limit, derived from `stack_bytes` in the original interpreter.
    pub gas_limit: u64,
    /// Token counter for XCall — starts at 0, increments per call.
    pub token_base: u64,

    /// Return value extracted by handler_return for the dispatcher.
    pub return_value: Option<u64>,

    pub host: Option<&'a CrossHost>,

    /// Operand data from the current instruction, passed from dispatcher to handler.
    /// For Push: operand_u64 is the value to push.
    /// For LoadArg/LoadLocal/StoreLocal: operand_u8 is the index.
    /// For LoadStorage/StoreStorage: operand_u64 is the slot.
    /// For Hash: operand_u8 is the word count (1..=8).
    /// For Jump/JumpIfFalse/Emit: operand_u32 is the target/topic.
    /// For LoadData/StoreData: operand_u64 is the offset.
    /// For XCall: operand_u16 is the arg_count.
    pub operand_u64: u64,
    pub operand_u32: u32,
    pub operand_u16: u16,
    pub operand_u8: u8,
}

impl<'a> ExecutionContext<'a> {
    pub fn push(&mut self, value: u64) -> Result<(), VmError> {
        if self.stack.len() >= MAX_STACK {
            return Err(VmError::StackOverflow);
        }
        self.stack.push(value);
        Ok(())
    }

    pub fn pop(&mut self) -> Result<u64, VmError> {
        self.stack.pop().ok_or(VmError::StackUnderflow)
    }

    /// Read a `u64` from the data stack at the given byte offset (little-endian).
    pub fn read_data_u64(&self, offset: u64) -> Result<u64, VmError> {
        let start = offset as usize;
        let end = start.checked_add(8).ok_or(VmError::DataStackOverflow)?;
        if end > self.data.len() {
            return Err(VmError::DataStackOverflow);
        }
        let bytes: [u8; 8] = self.data[start..end]
            .try_into()
            .expect("checked range above");
        Ok(u64::from_le_bytes(bytes))
    }

    /// Write a `u64` to the data stack at the given byte offset (little-endian).
    pub fn write_data_u64(&mut self, offset: u64, value: u64) -> Result<(), VmError> {
        let start = offset as usize;
        let end = start.checked_add(8).ok_or(VmError::DataStackOverflow)?;
        if end > self.data.len() {
            return Err(VmError::DataStackOverflow);
        }
        self.data[start..end].copy_from_slice(&value.to_le_bytes());
        Ok(())
    }

    /// Load from storage slot, returning 0 for unset slots (matching BTreeMap's unwrap_or).
    pub fn load_storage(&self, slot: u64) -> u64 {
        *self.storage.get(&slot).unwrap_or(&0)
    }

    /// Store to storage slot. A value of 0 prunes the slot (matching old `storage.remove`).
    /// Enforces `MAX_STORAGE_SLOTS` limit.
    pub fn store_storage(&mut self, slot: u64, value: u64) -> Result<(), VmError> {
        if value == 0 {
            self.storage.remove(&slot);
            return Ok(());
        }
        if self.storage.contains_key(&slot) || self.storage.len() < crate::MAX_STORAGE_SLOTS {
            self.storage.insert(slot, value);
            Ok(())
        } else {
            Err(VmError::StorageLimitExceeded)
        }
    }

    /// Pop eight words from the stack (top first), assemble into a Hash.
    /// Used by XCall and ReadReply for cross-message identifiers.
    pub fn pop_eight_words_to_hash(&mut self) -> Result<Hash, VmError> {
        let mut words = [0u64; 8];
        for word in words.iter_mut().rev() {
            *word = self.pop()?;
        }
        Ok(Hash(crate::words_to_hash_bytes(&words)))
    }
}
