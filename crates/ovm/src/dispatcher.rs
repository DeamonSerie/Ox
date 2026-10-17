//! OVM dispatcher — scans instructions and dispatches to compiled opcode handlers.
//!
//! The dispatcher iterates over the already-decoded `Program.instructions` vector.
//! For each instruction, it extracts any embedded operands into the `ExecutionContext`
//! and dispatches to the matching handler function via the dispatch table.

use crate::{
    context::ExecutionContext, opcode::get_handler, Execution, ExecutionFailure, Instruction,
    Program, VmError,
};

/// Result of dispatch — either completed execution or an error.
pub(crate) enum DispatchResult {
    Completed { return_value: Option<u64> },
    Reverted,
    OutOfGas,
    Error(VmError),
}

/// Scans the program's instruction list and dispatches each opcode to its
/// pre-compiled handler via the dispatch table.
///
/// This is the "scan and run" step: it iterates instructions and dispatches
/// each to its inline-asm-compiled handler. Gas is metered via `ctx.check_gas()`.
pub(crate) fn dispatch(program: &Program, ctx: &mut ExecutionContext) -> DispatchResult {
    let instructions = &program.instructions;
    let count = instructions.len();

    while ctx.pc < count {
        // Gas check before executing
        if ctx.instructions_used >= ctx.gas_limit {
            return DispatchResult::OutOfGas;
        }
        ctx.instructions_used += 1;

        let instruction = &instructions[ctx.pc];

        // Extract embedded operands into context for the handler
        match instruction {
            Instruction::Push(value) => {
                ctx.operand_u64 = *value;
            }
            Instruction::LoadArg(index) => {
                ctx.operand_u8 = *index;
            }
            Instruction::LoadLocal(index) => {
                ctx.operand_u8 = *index;
            }
            Instruction::StoreLocal(index) => {
                ctx.operand_u8 = *index;
            }
            Instruction::LoadStorage(slot) => {
                ctx.operand_u64 = *slot;
            }
            Instruction::StoreStorage(slot) => {
                ctx.operand_u64 = *slot;
            }
            Instruction::Hash { words } => {
                ctx.operand_u8 = *words;
            }
            Instruction::LoadStorageDyn => {}
            Instruction::StoreStorageDyn => {}
            Instruction::Jump(target) => {
                ctx.operand_u32 = *target;
            }
            Instruction::JumpIfFalse(target) => {
                ctx.operand_u32 = *target;
            }
            Instruction::Emit(topic) => {
                ctx.operand_u32 = *topic;
            }
            Instruction::XCall { arg_count } => {
                ctx.operand_u16 = *arg_count;
            }
            Instruction::LoadData(offset) => {
                ctx.operand_u64 = *offset;
            }
            Instruction::StoreData(offset) => {
                ctx.operand_u64 = *offset;
            }
            _ => {}
        }

        // Get handler from dispatch table and execute
        let handler = get_handler(instruction);

        // Handle PC advancement — for Jump/JumpIfFalse, the handler sets ctx.pc directly
        let pc_before = ctx.pc;
        match handler(ctx) {
            Ok(()) => {
                // If pc hasn't changed, advance to next instruction
                if ctx.pc == pc_before {
                    ctx.pc += 1;
                }
            }
            Err(VmError::Reverted) => {
                return DispatchResult::Reverted;
            }
            Err(error) => {
                return DispatchResult::Error(error);
            }
        }

        // Check for Return signal — handler sets pc to usize::MAX
        if ctx.pc == usize::MAX {
            return DispatchResult::Completed {
                return_value: ctx.return_value,
            };
        }
    }

    DispatchResult::Error(VmError::MissingReturn)
}

/// Scans the program's instruction list and dispatches each opcode to its
/// pre-compiled handler. Converts the result into an `Execution` or `ExecutionFailure`.
pub(crate) fn run_program(
    program: &Program,
    ctx: &mut ExecutionContext,
) -> Result<crate::Execution, crate::ExecutionFailure> {
    let gas_used = ctx.gas_limit;
    match dispatch(program, ctx) {
        DispatchResult::Completed { return_value } => Ok(Execution {
            return_value,
            gas_used,
            logs: std::mem::take(&mut ctx.logs),
            storage: std::mem::take(&mut ctx.storage),
            staged_calls: std::mem::take(&mut ctx.staged_calls),
        }),
        DispatchResult::Reverted => Err(ExecutionFailure {
            error: VmError::Reverted,
            gas_used,
        }),
        DispatchResult::OutOfGas => Err(ExecutionFailure {
            error: VmError::OutOfGas,
            gas_used,
        }),
        DispatchResult::Error(error) => Err(ExecutionFailure { error, gas_used }),
    }
}
