//! OVM opcode handler implementations.
//!
//! Arithmetic opcodes use inline `asm!` to compile to native x86-64 instructions at build time.
//! On non-x86_64 targets, fallback pure-Rust implementations are used.
//!
//! The dispatcher sets `ctx.operand_*` fields with the current instruction's embedded data
//! before calling each handler.

use crate::{context::ExecutionContext, VmError, MAX_CROSS_ARGUMENTS};
use oxydome_crypto::Hash;

// =============================================================================
// Stack operations
// =============================================================================

#[inline]
pub(crate) fn handle_push(ctx: &mut ExecutionContext) -> Result<(), VmError> {
    ctx.push(ctx.operand_u64)
}

#[inline]
pub(crate) fn handle_load_arg(ctx: &mut ExecutionContext) -> Result<(), VmError> {
    let idx = ctx.operand_u8 as usize;
    if idx >= ctx.arguments.len() {
        return Err(VmError::ArgumentCount);
    }
    ctx.push(ctx.arguments[idx])
}

#[inline]
pub(crate) fn handle_load_local(ctx: &mut ExecutionContext) -> Result<(), VmError> {
    let idx = ctx.operand_u8 as usize;
    if idx >= ctx.locals.len() {
        return Err(VmError::InvalidLocal);
    }
    ctx.push(ctx.locals[idx])
}

#[inline]
pub(crate) fn handle_store_local(ctx: &mut ExecutionContext) -> Result<(), VmError> {
    let idx = ctx.operand_u8 as usize;
    if idx >= ctx.locals.len() {
        return Err(VmError::InvalidLocal);
    }
    let value = ctx.pop()?;
    ctx.locals[idx] = value;
    Ok(())
}

// =============================================================================
// Storage operations
// =============================================================================

#[inline]
pub(crate) fn handle_load_storage(ctx: &mut ExecutionContext) -> Result<(), VmError> {
    let slot = ctx.operand_u64;
    ctx.push(ctx.load_storage(slot))
}

#[inline]
pub(crate) fn handle_store_storage(ctx: &mut ExecutionContext) -> Result<(), VmError> {
    let slot = ctx.operand_u64;
    let value = ctx.pop()?;
    ctx.store_storage(slot, value)
}

#[inline]
pub(crate) fn handle_hash(ctx: &mut ExecutionContext) -> Result<(), VmError> {
    let words = ctx.operand_u8 as usize;
    let mut parts: Vec<u64> = Vec::with_capacity(words);
    for _ in 0..words {
        parts.push(ctx.pop()?);
    }
    // parts are in pop order (top first); reverse so the bottom-of-stack
    // word comes first in the byte stream.
    parts.reverse();
    let mut input = Vec::with_capacity(words * 8);
    for word in parts {
        input.extend_from_slice(&word.to_le_bytes());
    }
    let digest = oxydome_crypto::hash(&input);
    let result = u64::from_le_bytes(digest.0[..8].try_into().expect("8-byte slice"));
    ctx.push(result)
}

#[inline]
pub(crate) fn handle_load_storage_dyn(ctx: &mut ExecutionContext) -> Result<(), VmError> {
    let slot = ctx.pop()?;
    ctx.push(ctx.load_storage(slot))
}

#[inline]
pub(crate) fn handle_store_storage_dyn(ctx: &mut ExecutionContext) -> Result<(), VmError> {
    let value = ctx.pop()?;
    let slot = ctx.pop()?;
    ctx.store_storage(slot, value)
}

// =============================================================================
// Data stack operations
// =============================================================================

#[inline]
pub(crate) fn handle_data_size(ctx: &mut ExecutionContext) -> Result<(), VmError> {
    ctx.push(ctx.gas_limit)
}

#[inline]
pub(crate) fn handle_load_data(ctx: &mut ExecutionContext) -> Result<(), VmError> {
    let offset = ctx.operand_u64;
    ctx.push(ctx.read_data_u64(offset)?)
}

#[inline]
pub(crate) fn handle_store_data(ctx: &mut ExecutionContext) -> Result<(), VmError> {
    let offset = ctx.operand_u64;
    let value = ctx.pop()?;
    ctx.write_data_u64(offset, value)
}

// =============================================================================
// Control flow
// =============================================================================

#[inline]
pub(crate) fn handle_jump(ctx: &mut ExecutionContext) -> Result<(), VmError> {
    let target = ctx.operand_u32 as usize;
    ctx.pc = target;
    Ok(())
}

#[inline]
pub(crate) fn handle_jump_if_false(ctx: &mut ExecutionContext) -> Result<(), VmError> {
    let target = ctx.operand_u32 as usize;
    let value = ctx.pop()?;
    if value == 0 {
        ctx.pc = target;
    }
    Ok(())
}

#[inline]
pub(crate) fn handle_emit(ctx: &mut ExecutionContext) -> Result<(), VmError> {
    let topic = ctx.operand_u32;
    let value = ctx.pop()?;
    ctx.logs.push(crate::Log { topic, value });
    Ok(())
}

// =============================================================================
// Return — signals completion to dispatcher
// =============================================================================

#[inline]
pub(crate) fn handle_return(ctx: &mut ExecutionContext) -> Result<(), VmError> {
    let return_value = if ctx.stack.is_empty() {
        None
    } else {
        Some(ctx.pop()?)
    };
    ctx.return_value = return_value;
    ctx.pc = usize::MAX;
    Ok(())
}

// =============================================================================
// Revert
// =============================================================================

#[inline]
pub(crate) fn handle_revert(_ctx: &mut ExecutionContext) -> Result<(), VmError> {
    Err(VmError::Reverted)
}

// =============================================================================
// Arithmetic with inline asm (x86-64)
// =============================================================================

#[inline]
pub(crate) fn handle_add(ctx: &mut ExecutionContext) -> Result<(), VmError> {
    let rhs = ctx.pop()?;
    let lhs = ctx.pop()?;
    let result: u64;
    let overflow: u8;
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let acc = lhs;
        core::arch::asm!(
            "add {0}, {1}",
            "setc {2}",
            inout(reg) acc => result,
            in(reg) rhs,
            out(reg_byte) overflow,
            options(nostack),
        );
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let (r, of) = lhs.overflowing_add(rhs);
        result = r;
        overflow = if of { 1 } else { 0 };
    }
    if overflow != 0 {
        return Err(VmError::ArithmeticOverflow);
    }
    ctx.push(result)
}

#[inline]
pub(crate) fn handle_sub(ctx: &mut ExecutionContext) -> Result<(), VmError> {
    let rhs = ctx.pop()?;
    let lhs = ctx.pop()?;
    let result: u64;
    let overflow: u8;
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let acc = lhs;
        core::arch::asm!(
            "sub {0}, {1}",
            "setc {2}",
            inout(reg) acc => result,
            in(reg) rhs,
            out(reg_byte) overflow,
            options(nostack),
        );
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let (r, of) = lhs.overflowing_sub(rhs);
        result = r;
        overflow = if of { 1 } else { 0 };
    }
    if overflow != 0 {
        return Err(VmError::ArithmeticOverflow);
    }
    ctx.push(result)
}

#[inline]
pub(crate) fn handle_mul(ctx: &mut ExecutionContext) -> Result<(), VmError> {
    let rhs = ctx.pop()?;
    let lhs = ctx.pop()?;
    let result: u64;
    let overflow: u8;
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let hi: u64;
        core::arch::asm!(
            "mul {rhs}",
            inlateout("rax") lhs => result,
            rhs = in(reg) rhs,
            out("rdx") hi,
            options(nostack, nomem),
        );
        overflow = if hi != 0 { 1 } else { 0 };
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let (r, of) = lhs.overflowing_mul(rhs);
        result = r;
        overflow = if of { 1 } else { 0 };
    }
    if overflow != 0 {
        return Err(VmError::ArithmeticOverflow);
    }
    ctx.push(result)
}

#[inline]
pub(crate) fn handle_div(ctx: &mut ExecutionContext) -> Result<(), VmError> {
    let rhs = ctx.pop()?;
    let lhs = ctx.pop()?;
    if rhs == 0 {
        return Err(VmError::DivisionByZero);
    }
    let result: u64;
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "mov rax, {0}",
            "xor rdx, rdx",
            "div {1}",
            "mov {2}, rax",
            in(reg) lhs,
            in(reg) rhs,
            out(reg) result,
            options(pure, nostack, nomem),
        );
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        result = lhs / rhs;
    }
    ctx.push(result)
}

#[inline]
pub(crate) fn handle_mod(ctx: &mut ExecutionContext) -> Result<(), VmError> {
    let rhs = ctx.pop()?;
    let lhs = ctx.pop()?;
    if rhs == 0 {
        return Err(VmError::DivisionByZero);
    }
    let result: u64;
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "mov rax, {0}",
            "xor rdx, rdx",
            "div {1}",
            "mov {2}, rdx",
            in(reg) lhs,
            in(reg) rhs,
            out(reg) result,
            options(pure, nostack, nomem),
        );
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        result = lhs % rhs;
    }
    ctx.push(result)
}

// =============================================================================
// Bitwise operations with inline asm (x86-64)
// =============================================================================

#[inline]
pub(crate) fn handle_and(ctx: &mut ExecutionContext) -> Result<(), VmError> {
    let rhs = ctx.pop()?;
    let lhs = ctx.pop()?;
    let result: u64;
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "and {0}, {1}",
            inout(reg) lhs => result,
            in(reg) rhs,
            options(pure, nostack, nomem),
        );
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        result = lhs & rhs;
    }
    ctx.push(result)
}

#[inline]
pub(crate) fn handle_or(ctx: &mut ExecutionContext) -> Result<(), VmError> {
    let rhs = ctx.pop()?;
    let lhs = ctx.pop()?;
    let result: u64;
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "or {0}, {1}",
            inout(reg) lhs => result,
            in(reg) rhs,
            options(pure, nostack, nomem),
        );
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        result = lhs | rhs;
    }
    ctx.push(result)
}

#[inline]
pub(crate) fn handle_bit_xor(ctx: &mut ExecutionContext) -> Result<(), VmError> {
    let rhs = ctx.pop()?;
    let lhs = ctx.pop()?;
    let result: u64;
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "xor {0}, {1}",
            inout(reg) lhs => result,
            in(reg) rhs,
            options(pure, nostack, nomem),
        );
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        result = lhs ^ rhs;
    }
    ctx.push(result)
}

#[inline]
pub(crate) fn handle_shl(ctx: &mut ExecutionContext) -> Result<(), VmError> {
    let rhs = ctx.pop()?;
    let lhs = ctx.pop()?;
    let result: u64;
    #[cfg(target_arch = "x86_64")]
    unsafe {
        // x86_64 shl requires shift count in CL register (masked to 6 bits by CPU)
        // We use `in("cl")` to constrain the shift amount to CL
        let shift_amount = (rhs & 63) as u8;
        core::arch::asm!(
            "shl {0}, cl",
            inout(reg) lhs => result,
            in("cl") shift_amount,
            options(pure, nostack, nomem),
        );
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        result = if rhs >= 64 { 0 } else { lhs << rhs };
    }
    ctx.push(result)
}

#[inline]
pub(crate) fn handle_shr(ctx: &mut ExecutionContext) -> Result<(), VmError> {
    let rhs = ctx.pop()?;
    let lhs = ctx.pop()?;
    let result: u64;
    #[cfg(target_arch = "x86_64")]
    unsafe {
        // x86_64 shr requires shift count in CL register (masked to 6 bits by CPU)
        let shift_amount = (rhs & 63) as u8;
        core::arch::asm!(
            "shr {0}, cl",
            inout(reg) lhs => result,
            in("cl") shift_amount,
            options(pure, nostack, nomem),
        );
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        result = if rhs >= 64 { 0 } else { lhs >> rhs };
    }
    ctx.push(result)
}

#[inline]
pub(crate) fn handle_not(ctx: &mut ExecutionContext) -> Result<(), VmError> {
    let value = ctx.pop()?;
    // Logical NOT: 0 → 1, anything else → 0
    let result: u64;
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let is_zero: u8;
        core::arch::asm!(
            "test {0}, {0}",
            "sete {1}",
            in(reg) value,
            out(reg_byte) is_zero,
            options(pure, nostack, nomem),
        );
        result = is_zero as u64;
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        result = u64::from(value == 0);
    }
    ctx.push(result)
}

// =============================================================================
// Comparison operations with inline asm (x86-64)
// =============================================================================

#[inline]
pub(crate) fn handle_equal(ctx: &mut ExecutionContext) -> Result<(), VmError> {
    let rhs = ctx.pop()?;
    let lhs = ctx.pop()?;
    let result: u8;
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "cmp {0}, {1}",
            "sete {2}",
            in(reg) rhs,
            in(reg) lhs,
            out(reg_byte) result,
            options(pure, nostack, nomem),
        );
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        result = u8::from(lhs == rhs);
    }
    ctx.push(u64::from(result != 0))
}

#[inline]
pub(crate) fn handle_less_than(ctx: &mut ExecutionContext) -> Result<(), VmError> {
    let rhs = ctx.pop()?;
    let lhs = ctx.pop()?;
    let result: u8;
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "cmp {1}, {0}",
            "setb {2}",
            in(reg) rhs,
            in(reg) lhs,
            out(reg_byte) result,
            options(pure, nostack, nomem),
        );
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        result = u8::from(lhs < rhs);
    }
    ctx.push(u64::from(result != 0))
}

#[inline]
pub(crate) fn handle_greater_than(ctx: &mut ExecutionContext) -> Result<(), VmError> {
    let rhs = ctx.pop()?;
    let lhs = ctx.pop()?;
    let result: u8;
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "cmp {1}, {0}",
            "seta {2}",
            in(reg) rhs,
            in(reg) lhs,
            out(reg_byte) result,
            options(pure, nostack, nomem),
        );
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        result = u8::from(lhs > rhs);
    }
    ctx.push(u64::from(result != 0))
}

// =============================================================================
// XCall: stages a cross-OHM message
//
// Pop order (top of stack first):
//   1. gas_limit
//   2. entry_selector
//   3-10. eight target_contract words (reversed)
//   11-18. eight target_ohm words (reversed)
//   19+. arg_count payload words (reversed)
//
// Pushes the staged-call token.
// =============================================================================

pub(crate) fn handle_xcall(ctx: &mut ExecutionContext) -> Result<(), VmError> {
    // Check host presence before popping — matches original interpreter behavior
    if ctx.host.is_none() {
        return Err(VmError::InvalidProgram);
    }
    let arg_count = ctx.operand_u16 as usize;
    if arg_count > MAX_CROSS_ARGUMENTS {
        return Err(VmError::InvalidProgram);
    }
    let gas_limit = ctx.pop()?;
    let entry_selector = ctx.pop()?;

    let mut contract_words = [0u64; 8];
    for word in contract_words.iter_mut().rev() {
        *word = ctx.pop()?;
    }
    let target_contract = Hash(crate::words_to_hash_bytes(&contract_words));

    let mut ohm_words = [0u64; 8];
    for word in ohm_words.iter_mut().rev() {
        *word = ctx.pop()?;
    }
    let target_ohm = Hash(crate::words_to_hash_bytes(&ohm_words));

    let mut arguments = Vec::with_capacity(arg_count);
    for _ in 0..arg_count {
        arguments.push(ctx.pop()?);
    }
    arguments.reverse();

    let token = ctx.token_base;
    ctx.staged_calls.push(crate::StagedCrossCall {
        token,
        target_ohm,
        target_contract,
        entry_selector,
        gas_limit,
        arguments,
    });
    ctx.token_base += 1;
    ctx.push(token)
}

// =============================================================================
// ReadReply: reads a receipt from the host inbox
//
// Pops eight words (top first), assembles into a Hash (msg_id),
// looks up in host.inbox, pushes (success, value) to stack.
// =============================================================================

pub(crate) fn handle_read_reply(ctx: &mut ExecutionContext) -> Result<(), VmError> {
    let host = match ctx.host {
        Some(host) => host,
        None => return Err(VmError::InvalidProgram),
    };

    let msg_id = ctx.pop_eight_words_to_hash()?;
    let view = host
        .inbox
        .get(&msg_id)
        .copied()
        .unwrap_or(crate::ReceiptView {
            success: false,
            value: 0,
        });

    ctx.push(u64::from(view.success))?;
    ctx.push(view.value)
}

// =============================================================================
// =============================================================================
// LoadPriceBounds: loads packed price bounds for an asset from the host oracle.
//
// Pops: asset_id (u64)
// Pushes: upper_bound, lower_bound, bound_price_position, midpoint, current_price
//   (u64 each, top first means current_price is pushed last and is on top of the stack).
// =============================================================================

pub(crate) fn handle_load_price_bounds(ctx: &mut ExecutionContext) -> Result<(), VmError> {
    let host = match ctx.host {
        Some(host) => host,
        None => return Err(VmError::InvalidProgram),
    };
    let oracle = match &host.price_oracle {
        Some(oracle) => oracle,
        None => return Err(VmError::InvalidProgram),
    };
    let asset_id = ctx.pop()?;
    let bounds = oracle
        .bounds
        .get(&asset_id)
        .ok_or(VmError::InvalidProgram)?;
    ctx.push(bounds.upper_bound)?;
    ctx.push(bounds.lower_bound)?;
    ctx.push(bounds.bound_price_position)?;
    ctx.push(bounds.midpoint)?;
    ctx.push(bounds.current_price)
}

// =============================================================================
// PeggedConvert: guaranteed exchange-rate conversion from the main currency to a
// priced asset, as long as the asset's price is within the upper half of the band.
//
// Pops: amount, asset_id (top first)
// Pushes: converted_amount
//
// The host must carry a price_oracle. The asset's bounds must already be known
// to the contract (loaded via LoadPriceBounds). When the current price is in the
// upper half of the band (in bounds), the pegged token is equal to the main OX
// currency, so the conversion is 1:1. When out of bounds, the conversion fails.
// =============================================================================

pub(crate) fn handle_pegged_convert(ctx: &mut ExecutionContext) -> Result<(), VmError> {
    let host = match ctx.host {
        Some(host) => host,
        None => return Err(VmError::InvalidProgram),
    };
    let oracle = match &host.price_oracle {
        Some(oracle) => oracle,
        None => return Err(VmError::InvalidProgram),
    };
    let asset_id = ctx.pop()?;
    let amount = ctx.pop()?;
    let bounds = oracle
        .bounds
        .get(&asset_id)
        .ok_or(VmError::InvalidProgram)?;
    if bounds.upper_bound == 0 || bounds.midpoint == 0 {
        return Err(VmError::ArithmeticOverflow);
    }
    // In-bounds check: when the current price is in the upper half of the band
    // (>= midpoint), the pegged token equals the main OX currency (1:1).
    if bounds.current_price < bounds.midpoint {
        ctx.push(0)?;
        return Ok(());
    }
    ctx.push(amount)
}

// =============================================================================
// LoadPoolState: loads packed liquidity-pool state from the host oracle.
//
// Pops: pool_id (u64)
// Pushes: reserve_x, reserve_y, k, fee_bps (u64 each, top first — fee_bps ends on top)
// =============================================================================

pub(crate) fn handle_load_pool_state(ctx: &mut ExecutionContext) -> Result<(), VmError> {
    let host = match ctx.host {
        Some(host) => host,
        None => return Err(VmError::InvalidProgram),
    };
    let oracle = match &host.pool_oracle {
        Some(oracle) => oracle,
        None => return Err(VmError::InvalidProgram),
    };
    let pool_id = ctx.pop()?;
    let state = oracle.pools.get(&pool_id).ok_or(VmError::InvalidProgram)?;
    ctx.push(state.reserve_x)?;
    ctx.push(state.reserve_y)?;
    ctx.push(state.k)?;
    ctx.push(state.fee_bps)
}

// =============================================================================
// PoolSwap: constant-product AMM swap.
//
// Pops: input_amount, pool_id (top first)
// Pushes: output_amount
//
// The fee (fee_bps, in basis points) is deducted from the input before the
// constant-product formula. All arithmetic is done in u128 to avoid overflow:
//   effective_input = input_amount * (10000 - fee_bps) / 10000
//   new_x            = x_reserve + effective_input
//   new_y            = k / new_x
//   output           = y_reserve - new_y
// The result is packed back to u64 for OVM consumption.
// =============================================================================

pub(crate) fn handle_pool_swap(ctx: &mut ExecutionContext) -> Result<(), VmError> {
    let host = match ctx.host {
        Some(host) => host,
        None => return Err(VmError::InvalidProgram),
    };
    let oracle = match &host.pool_oracle {
        Some(oracle) => oracle,
        None => return Err(VmError::InvalidProgram),
    };
    // Pop order (top first): `input_amount`, then `pool_id`.
    let input_amount = ctx.pop()?;
    let pool_id = ctx.pop()?;
    let state = oracle.pools.get(&pool_id).ok_or(VmError::InvalidProgram)?;
    if state.k == 0 || state.reserve_x == 0 || state.reserve_y == 0 {
        return Err(VmError::ArithmeticOverflow);
    }
    let fee_bps = state.fee_bps;
    if fee_bps > 10_000 {
        return Err(VmError::ArithmeticOverflow);
    }
    let scale = crate::POOL_FP_SCALE as u128;
    let input_scaled = (input_amount as u128).saturating_mul(scale);
    let fee_multiplier = 10_000u128.saturating_sub(fee_bps as u128);
    let effective_input = input_scaled.saturating_mul(fee_multiplier) / 10_000u128;
    let x_reserve = (state.reserve_x as u128).saturating_mul(scale);
    let y_reserve = (state.reserve_y as u128).saturating_mul(scale);
    let k_scaled = (state.k as u128).saturating_mul(scale);
    let new_x = x_reserve.saturating_add(effective_input);
    if new_x == 0 {
        return Err(VmError::ArithmeticOverflow);
    }
    let new_y = k_scaled / new_x;
    if y_reserve <= new_y {
        return Err(VmError::ArithmeticOverflow);
    }
    let output = y_reserve.saturating_sub(new_y);
    // Record the swap so that the transaction can be recognised as a swap (the
    // verification-credit auction only accepts swaps).
    ctx.logs.push(crate::Log {
        topic: crate::POOL_SWAP_LOG_TOPIC,
        value: (output / scale) as u64,
    });
    ctx.push((output / scale) as u64)
}
