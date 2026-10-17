//! OpCode trait and dispatch table for OVM opcodes.
//!
//! The dispatch table maps each `Instruction` variant to a handler function pointer.
//! Handler functions contain inline `asm!` that compiles to native machine code at build time.

use crate::{context::ExecutionContext, VmError};

/// Function pointer type for opcode handlers.
pub(crate) type OpcodeHandler = fn(&mut ExecutionContext) -> Result<(), VmError>;

/// Dispatch table mapping Instruction variant index to its handler function.
/// Uses `OnceLock` for lazy, thread-safe initialization.
pub(crate) static OPCODE_TABLE: std::sync::OnceLock<Vec<OpcodeHandler>> =
    std::sync::OnceLock::new();

/// Returns the dispatch table index for each Instruction variant.
/// The order MUST match the order of entries in `init_opcode_table()`.
const fn instruction_index(instruction: &crate::Instruction) -> usize {
    use crate::Instruction::*;
    match instruction {
        Push(_) => 0,
        LoadArg(_) => 1,
        LoadLocal(_) => 2,
        StoreLocal(_) => 3,
        LoadStorage(_) => 4,
        StoreStorage(_) => 5,
        Hash { .. } => 6,
        StoreStorageDyn => 7,
        LoadStorageDyn => 8,
        Add => 9,
        Sub => 10,
        Mul => 11,
        Div => 12,
        Mod => 13,
        Equal => 14,
        LessThan => 15,
        GreaterThan => 16,
        And => 17,
        Or => 18,
        Not => 19,
        BitXor => 20,
        Shl => 21,
        Shr => 22,
        Jump(_) => 23,
        JumpIfFalse(_) => 24,
        Emit(_) => 25,
        XCall { .. } => 26,
        ReadReply => 27,
        Return => 28,
        Revert => 29,
        DataSize => 30,
        LoadData(_) => 31,
        StoreData(_) => 32,
        LoadPriceBounds => 33,
        PeggedConvert => 34,
        LoadPoolState => 35,
        PoolSwap => 36,
    }
}

/// Gets the handler for a given instruction from the dispatch table.
pub(crate) fn get_handler(instruction: &crate::Instruction) -> OpcodeHandler {
    let table = init_opcode_table();
    let index = instruction_index(instruction);
    table[index]
}

/// Initializes the opcode dispatch table by mapping all instruction variants to handlers.
/// The order MUST match `instruction_index()`.
pub(crate) fn init_opcode_table() -> &'static [OpcodeHandler] {
    OPCODE_TABLE.get_or_init(|| {
        use super::opcodes as op;
        vec![
            op::handle_push,
            op::handle_load_arg,
            op::handle_load_local,
            op::handle_store_local,
            op::handle_load_storage,
            op::handle_store_storage,
            op::handle_hash,
            op::handle_store_storage_dyn,
            op::handle_load_storage_dyn,
            op::handle_add,
            op::handle_sub,
            op::handle_mul,
            op::handle_div,
            op::handle_mod,
            op::handle_equal,
            op::handle_less_than,
            op::handle_greater_than,
            op::handle_and,
            op::handle_or,
            op::handle_not,
            op::handle_bit_xor,
            op::handle_shl,
            op::handle_shr,
            op::handle_jump,
            op::handle_jump_if_false,
            op::handle_emit,
            op::handle_xcall,
            op::handle_read_reply,
            op::handle_return,
            op::handle_revert,
            op::handle_data_size,
            op::handle_load_data,
            op::handle_store_data,
            op::handle_load_price_bounds,
            op::handle_pegged_convert,
            op::handle_load_pool_state,
            op::handle_pool_swap,
        ]
    })
}
