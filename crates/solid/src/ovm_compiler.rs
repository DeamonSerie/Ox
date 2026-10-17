use crate::ast::{Block, Contract, Expr, Function, LValue, Statement, Type, Visibility};
use crate::ovm_validation::{self, ValueType};
use oxydome_ovm::{
    ContractArtifact, ContractFunction, ContractValueType, Instruction, Program, VmError,
    AUTHORITY_WORD_COUNT,
};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CompileError {
    #[error("function `{0}` was not found")]
    FunctionNotFound(String),
    #[error("OVM compiler does not support: {0}")]
    Unsupported(String),
    #[error("OVM bytecode generation failed: {0}")]
    Bytecode(String),
    #[error("invalid DAO declaration: {0}")]
    InvalidDao(String),
    #[error("failed to parse Solid source: {0}")]
    Parse(String),
}

impl From<VmError> for CompileError {
    fn from(value: VmError) -> Self {
        Self::Bytecode(value.to_string())
    }
}

/// Compile one supported Solid function to deterministic OVM v1 bytecode.
///
/// The compiler currently supports scalar `u64` and `bool` values, scalar state,
/// expressions, conditionals, and bounded-by-gas loops. It does not add EVM semantics.
pub fn compile_function_to_ovm(
    contract: &Contract,
    function_name: &str,
) -> Result<Vec<u8>, CompileError> {
    let function = contract
        .functions
        .iter()
        .find(|function| function.name == function_name)
        .ok_or_else(|| CompileError::FunctionNotFound(function_name.to_owned()))?;
    ovm_validation::validate_function(contract, function)?;
    compile_function(contract, function, false)
}

/// Compile all externally callable functions of a Solid contract into a canonical OVM artifact.
///
/// Function names are the native OVM entry-point identifiers. Every call receives an
/// authenticated four-word transaction authority context before its declared arguments.
pub fn compile_contract_to_ovm(
    contract: &Contract,
    source_hash: Option<oxydome_crypto::Hash>,
    asset_manifest_hash: Option<oxydome_crypto::Hash>,
) -> Result<Vec<u8>, CompileError> {
    let mut functions = Vec::new();
    for function in &contract.functions {
        if !matches!(
            function.visibility,
            Visibility::Public | Visibility::External
        ) {
            continue;
        }
        ovm_validation::validate_function_with_context(contract, function, true)?;
        let code = compile_function(contract, function, true)?;
        let inputs = function
            .inputs
            .iter()
            .map(|param| artifact_type(&param.ty))
            .collect::<Result<Vec<_>, _>>()?;
        let output = function
            .outputs
            .first()
            .map(|param| artifact_type(&param.ty))
            .transpose()?;
        functions.push(ContractFunction {
            name: function.name.clone(),
            inputs,
            output,
            code,
        });
    }
    functions.sort_by(|left, right| left.name.cmp(&right.name));
    let artifact = ContractArtifact {
        source_hash,
        asset_manifest_hash,
        functions,
    };
    Ok(artifact.encode()?)
}

/// Compiled output for a Solid contract, keeping the ordinary OVM artifact separate from the
/// consensus-enforced DAO policy, timer configuration, and pegged currency artifacts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledSolid {
    pub contract_artifact: Vec<u8>,
    pub dao_policy: Option<Vec<u8>>,
    pub timer_config: Option<Vec<u8>>,
    pub pegged_config: Option<Vec<u8>>,
    pub liquidity_pool_config: Option<Vec<u8>>,
}

pub fn compile_solid_to_ovm(
    contract: &Contract,
    source_hash: Option<oxydome_crypto::Hash>,
    asset_manifest_hash: Option<oxydome_crypto::Hash>,
) -> Result<CompiledSolid, CompileError> {
    Ok(CompiledSolid {
        contract_artifact: compile_contract_to_ovm(contract, source_hash, asset_manifest_hash)?,
        dao_policy: compile_dao_policy(contract)?,
        timer_config: compile_timer_config(contract)?,
        pegged_config: compile_pegged_config(contract)?,
        liquidity_pool_config: compile_liquidity_pool_config(contract)?,
    })
}

/// Compile and canonically encode the timer configuration declared in Solid, if any.
pub fn compile_timer_config(contract: &Contract) -> Result<Option<Vec<u8>>, CompileError> {
    let Some(declaration) = &contract.timer else {
        return Ok(None);
    };
    let asset = if declaration.asset == "Ox" {
        oxydome_core::TimerAsset::Ox
    } else {
        let dao_id = oxydome_crypto::Hash(
            parse_fixed_hex::<64>(&declaration.asset)
                .map_err(|error| CompileError::InvalidDao(format!("timer asset: {error}")))?,
        );
        oxydome_core::TimerAsset::DaoCurrency { dao_id }
    };
    let direction = match declaration.direction.as_str() {
        "up" => oxydome_core::TimerDirection::Up,
        "down" => oxydome_core::TimerDirection::Down,
        other => {
            return Err(CompileError::InvalidDao(format!(
                "unknown timer direction: {other}"
            )))
        }
    };
    let config = oxydome_core::TimerConfig {
        asset,
        direction,
        duration_blocks: declaration.duration_blocks,
        price_anchor: declaration.price_anchor,
    };
    let bytes =
        bincode::serialize(&config).map_err(|error| CompileError::InvalidDao(error.to_string()))?;
    Ok(Some(bytes))
}

/// Compile and canonically encode the pegged currency configuration declared in Solid, if any.
pub fn compile_pegged_config(contract: &Contract) -> Result<Option<Vec<u8>>, CompileError> {
    let Some(declaration) = &contract.pegged_currency else {
        return Ok(None);
    };
    let asset = if declaration.asset == "Ox" {
        oxydome_core::PriceAsset::Ox
    } else if declaration.asset == "Gas" {
        oxydome_core::PriceAsset::Gas
    } else {
        let dao_id = oxydome_crypto::Hash(
            parse_fixed_hex::<64>(&declaration.asset)
                .map_err(|error| CompileError::InvalidDao(format!("pegged asset: {error}")))?,
        );
        oxydome_core::PriceAsset::DaoCurrency { dao_id }
    };
    let config = oxydome_core::PeggedCurrencyConfig {
        asset,
        spread_bps: declaration.spread_bps,
        pegged_numerator: declaration.pegged_numerator,
        pegged_denominator: declaration.pegged_denominator,
    };
    let bytes =
        bincode::serialize(&config).map_err(|error| CompileError::InvalidDao(error.to_string()))?;
    Ok(Some(bytes))
}

/// Compile and canonically encode the DAO policy declared in Solid, if any.
pub fn compile_dao_policy(contract: &Contract) -> Result<Option<Vec<u8>>, CompileError> {
    let Some(declaration) = &contract.dao else {
        return Ok(None);
    };
    let mut makers = declaration
        .makers
        .iter()
        .map(|maker| {
            parse_fixed_hex::<32>(maker)
                .map(oxydome_crypto::PublicKey)
                .map_err(|error| CompileError::InvalidDao(format!("maker address: {error}")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    makers.sort();
    let currency = declaration
        .currency
        .as_ref()
        .map(|currency| oxydome_core::DaoCurrency {
            symbol: currency.symbol.clone(),
            initial_supply: currency.initial_supply,
        });
    let peg = declaration
        .peg
        .as_ref()
        .map(|peg| -> Result<oxydome_core::DaoPeg, CompileError> {
            Ok(oxydome_core::DaoPeg {
                target_dao: oxydome_crypto::Hash(
                    parse_fixed_hex::<64>(&peg.target_dao).map_err(|error| {
                        CompileError::InvalidDao(format!("peg target: {error}"))
                    })?,
                ),
                numerator: peg.numerator,
                denominator: peg.denominator,
            })
        })
        .transpose()?;
    let policy = oxydome_core::DaoPolicy {
        version: oxydome_core::DAO_POLICY_VERSION,
        makers,
        currency,
        peg,
    };
    policy.encode().map(Some).map_err(CompileError::InvalidDao)
}

/// Compile and canonically encode the liquidity pool configuration declared in Solid, if any.
pub fn compile_liquidity_pool_config(contract: &Contract) -> Result<Option<Vec<u8>>, CompileError> {
    let Some(declaration) = &contract.liquidity_pool else {
        return Ok(None);
    };
    let currencies: Vec<oxydome_core::PriceAsset> = declaration
        .currencies
        .iter()
        .map(|s| -> Result<oxydome_core::PriceAsset, CompileError> {
            if s == "Ox" {
                Ok(oxydome_core::PriceAsset::Ox)
            } else if s == "Gas" {
                Ok(oxydome_core::PriceAsset::Gas)
            } else {
                let dao_id =
                    oxydome_crypto::Hash(parse_fixed_hex::<64>(s).map_err(|error| {
                        CompileError::InvalidDao(format!("pool asset: {error}"))
                    })?);
                Ok(oxydome_core::PriceAsset::DaoCurrency { dao_id })
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    let bytes = bincode::serialize(&currencies)
        .map_err(|error| CompileError::InvalidDao(error.to_string()))?;
    Ok(Some(bytes))
}

fn parse_fixed_hex<const N: usize>(value: &str) -> Result<[u8; N], String> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(value).map_err(|error| error.to_string())?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("expected {} bytes, received {}", N, bytes.len()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Binding {
    index: u64,
    ty: ValueType,
    kind: BindingKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum BindingKind {
    Local,
    Storage,
    Struct { struct_name: String },
    Mapping { key: ValueType, value: ValueType },
}

/// Per-contract storage layout: maps each state variable name to its base slot
/// and a description of what lives there (scalar, struct, or mapping).
#[derive(Debug, Clone)]
struct StorageLayout {
    /// var name → (base_slot, kind)
    entries: BTreeMap<String, (u64, StorageEntry)>,
    /// struct name → [(field_name, field_type, slot_offset)]
    struct_layouts: BTreeMap<String, Vec<(String, ValueType, u64)>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum StorageEntry {
    Scalar(ValueType),
    Struct {
        struct_name: String,
        field_count: u16,
    },
    Mapping {
        key: ValueType,
        value: ValueType,
    },
}

#[derive(Default)]
struct LoopContext {
    breaks: Vec<usize>,
    continues: Vec<usize>,
}

fn compile_function(
    contract: &Contract,
    function: &Function,
    authority_context: bool,
) -> Result<Vec<u8>, CompileError> {
    if contract.variables.len() > oxydome_ovm::MAX_STORAGE_SLOTS {
        return Err(unsupported(format!(
            "more than {} state variables",
            oxydome_ovm::MAX_STORAGE_SLOTS
        )));
    }
    let layout = build_storage_layout(contract)?;
    let mut storage = BTreeMap::new();
    for (name, (base_slot, entry)) in &layout.entries {
        let (kind, ty) = match entry {
            StorageEntry::Scalar(ty) => (BindingKind::Storage, *ty),
            StorageEntry::Struct { struct_name, .. } => (
                BindingKind::Struct {
                    struct_name: struct_name.clone(),
                },
                ValueType::U64,
            ),
            StorageEntry::Mapping { key, value } => (
                BindingKind::Mapping {
                    key: *key,
                    value: *value,
                },
                ValueType::U64,
            ),
        };
        storage.insert(
            name.clone(),
            Binding {
                index: *base_slot,
                ty,
                kind,
            },
        );
    }

    let output = function
        .outputs
        .first()
        .map(|param| value_type(&param.ty))
        .transpose()?;
    let mut compiler = FunctionCompiler {
        instructions: Vec::new(),
        args: BTreeMap::new(),
        storage,
        struct_layouts: layout.struct_layouts.clone(),
        scopes: vec![BTreeMap::new()],
        local_count: 0,
        output,
        loops: Vec::new(),
        argument_offset: if authority_context {
            AUTHORITY_WORD_COUNT
        } else {
            0
        },
    };
    for (argument_index, param) in function.inputs.iter().enumerate() {
        if param.name.is_empty() {
            continue;
        }
        let ty = value_type(&param.ty)?;
        let local_index = compiler.allocate_local()?;
        compiler.instructions.push(Instruction::LoadArg(
            u8::try_from(argument_index + compiler.argument_offset)
                .map_err(|_| unsupported("too many function arguments"))?,
        ));
        if ty == ValueType::Bool {
            compiler.normalize_boolean();
        }
        compiler
            .instructions
            .push(Instruction::StoreLocal(local_index));
        compiler.args.insert(
            param.name.clone(),
            Binding {
                index: local_index as u64,
                ty,
                kind: BindingKind::Local,
            },
        );
    }
    compiler.block(&function.body, false)?;

    // This sentinel makes end-of-block jump destinations valid even when the last
    // source statement itself terminates. Validation ensures a value-returning function
    // cannot reach the fallback.
    match output {
        Some(_) => compiler.instructions.push(Instruction::Revert),
        None => compiler.instructions.push(Instruction::Return),
    }

    let program = Program {
        argument_count: u8::try_from(function.inputs.len())
            .ok()
            .and_then(|count| count.checked_add(compiler.argument_offset as u8))
            .ok_or_else(|| unsupported("too many function arguments"))?,
        local_count: compiler.local_count,
        instructions: compiler.instructions,
    };
    Ok(program.encode()?)
}

/// Build the storage layout for a contract, assigning base slots to each state
/// variable. Structs occupy N consecutive slots (one per field); mappings and
/// scalars each occupy one slot.
fn build_storage_layout(contract: &Contract) -> Result<StorageLayout, CompileError> {
    let mut struct_layouts: BTreeMap<String, Vec<(String, ValueType, u64)>> = BTreeMap::new();
    for struct_def in &contract.structs {
        let mut fields = Vec::new();
        for (offset, field) in struct_def.fields.iter().enumerate() {
            let ty = ovm_validation::ValueType::from_solid(&field.ty).map_err(|_| {
                unsupported(format!(
                    "struct `{}` field `{}` has unsupported type {:?}",
                    struct_def.name, field.name, field.ty
                ))
            })?;
            fields.push((field.name.clone(), ty, offset as u64));
        }
        struct_layouts.insert(struct_def.name.clone(), fields);
    }

    let mut entries = BTreeMap::new();
    let mut next_slot = 0u64;
    for variable in &contract.variables {
        let entry = match &variable.ty {
            Type::Named(name) => {
                let fields = struct_layouts
                    .get(name)
                    .ok_or_else(|| unsupported(format!("unknown named type `{name}`")))?;
                let field_count = fields.len() as u16;
                StorageEntry::Struct {
                    struct_name: name.clone(),
                    field_count,
                }
            }
            Type::Mapping { key, value } => {
                let key_ty = ovm_validation::ValueType::from_solid(key).map_err(|_| {
                    unsupported(format!("mapping key type {:?} is not supported", key))
                })?;
                let value_kind = state_var_kind(&value, &struct_layouts)?;
                let value_ty = match value_kind {
                    StateKind::Scalar(ty) => ty,
                    StateKind::Struct { .. } => {
                        return Err(unsupported(
                            "mapping value type struct is not yet supported",
                        ))
                    }
                    StateKind::Mapping { .. } => {
                        return Err(unsupported(
                            "nested mappings as mapping values are not yet supported",
                        ))
                    }
                };
                StorageEntry::Mapping {
                    key: key_ty,
                    value: value_ty,
                }
            }
            _ => {
                let ty = value_type(&variable.ty)?;
                StorageEntry::Scalar(ty)
            }
        };
        entries.insert(variable.name.clone(), (next_slot, entry));
        next_slot = next_slot.saturating_add(match &entries[&variable.name].1 {
            StorageEntry::Scalar(_) => 1,
            StorageEntry::Struct { field_count, .. } => *field_count as u64,
            StorageEntry::Mapping { .. } => 1,
        });
    }

    Ok(StorageLayout {
        struct_layouts,
        entries,
    })
}

/// Resolve a `Type` into a compiler `StateKind` (mirrors the validation side).
fn state_var_kind(
    ty: &Type,
    struct_layouts: &BTreeMap<String, Vec<(String, ValueType, u64)>>,
) -> Result<StateKind, CompileError> {
    match ty {
        Type::Named(name) => {
            if struct_layouts.contains_key(name) {
                Ok(StateKind::Struct { name: name.clone() })
            } else {
                Err(unsupported(format!("unknown named type `{name}`")))
            }
        }
        Type::Mapping { key, value } => {
            let key_ty = ovm_validation::ValueType::from_solid(key)
                .map_err(|_| unsupported(format!("mapping key type {:?} is not supported", key)))?;
            let value_kind = state_var_kind(value, struct_layouts)?;
            match value_kind {
                StateKind::Scalar(ty) => Ok(StateKind::Mapping {
                    key: key_ty,
                    value: ty,
                }),
                _ => Err(unsupported("nested type in mapping value is not supported")),
            }
        }
        _ => ovm_validation::ValueType::from_solid(ty).map(StateKind::Scalar),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum StateKind {
    Scalar(ValueType),
    Struct { name: String },
    Mapping { key: ValueType, value: ValueType },
}

fn value_type(ty: &Type) -> Result<ValueType, CompileError> {
    match ty {
        Type::U64 => Ok(ValueType::U64),
        Type::Bool => Ok(ValueType::Bool),
        Type::Address => Ok(ValueType::Address),
        _ => Err(unsupported(format!("type {ty:?}"))),
    }
}

fn artifact_type(ty: &Type) -> Result<ContractValueType, CompileError> {
    match value_type(ty)? {
        ValueType::U64 => Ok(ContractValueType::U64),
        ValueType::Bool => Ok(ContractValueType::Bool),
        ValueType::Address => Ok(ContractValueType::Address),
    }
}

fn unsupported(message: impl Into<String>) -> CompileError {
    CompileError::Unsupported(message.into())
}

struct FunctionCompiler {
    instructions: Vec<Instruction>,
    args: BTreeMap<String, Binding>,
    storage: BTreeMap<String, Binding>,
    struct_layouts: BTreeMap<String, Vec<(String, ValueType, u64)>>,
    scopes: Vec<BTreeMap<String, Binding>>,
    local_count: u8,
    output: Option<ValueType>,
    loops: Vec<LoopContext>,
    argument_offset: usize,
}

impl FunctionCompiler {
    fn block(&mut self, block: &Block, nested: bool) -> Result<(), CompileError> {
        if nested {
            self.scopes.push(BTreeMap::new());
        }
        for statement in &block.statements {
            self.statement(statement)?;
        }
        if nested {
            self.scopes.pop();
        }
        Ok(())
    }

    fn statement(&mut self, statement: &Statement) -> Result<(), CompileError> {
        match statement {
            Statement::Let { name, ty, init } => {
                let ty = value_type(ty)?;
                if let Some(init) = init {
                    self.expr(init)?;
                } else {
                    self.instructions.push(Instruction::Push(0));
                }
                let index = self.allocate_local()?;
                self.instructions.push(Instruction::StoreLocal(index));
                self.scopes
                    .last_mut()
                    .expect("function scope exists")
                    .insert(
                        name.clone(),
                        Binding {
                            index: index as u64,
                            ty,
                            kind: BindingKind::Local,
                        },
                    );
            }
            Statement::Assign { target, value } => match target {
                LValue::Index { base, index } => {
                    let binding = self.lvalue_ident(base)?;
                    let (base_slot, (key_ty, value_ty)) = self.mapping_info(&binding)?;
                    let _ = (key_ty, value_ty);
                    self.instructions.push(Instruction::Push(base_slot));
                    let _ = self.expr(index)?;
                    self.instructions.push(Instruction::Hash { words: 2 });
                    self.expr(value)?;
                    self.instructions.push(Instruction::StoreStorageDyn);
                }
                _ => {
                    self.expr(value)?;
                    let binding = self.lvalue(target)?;
                    self.store(binding);
                }
            },
            Statement::If {
                condition,
                true_block,
                false_block,
            } => {
                self.expr(condition)?;
                let false_jump = self.emit_jump_if_false();
                self.block(true_block, true)?;
                if let Some(false_block) = false_block {
                    let end_jump = self.emit_jump();
                    self.patch_jump(false_jump, self.instructions.len())?;
                    self.block(false_block, true)?;
                    self.patch_jump(end_jump, self.instructions.len())?;
                } else {
                    self.patch_jump(false_jump, self.instructions.len())?;
                }
            }
            Statement::For {
                init,
                cond,
                update,
                block,
            } => {
                self.scopes.push(BTreeMap::new());
                if let Some(init) = init {
                    self.statement(init)?;
                }
                let condition_start = self.instructions.len();
                let exit_jump = if let Some(condition) = cond {
                    self.expr(condition)?;
                    Some(self.emit_jump_if_false())
                } else {
                    None
                };

                self.loops.push(LoopContext::default());
                self.block(block, true)?;
                let update_start = self.instructions.len();
                self.patch_loop_continues(update_start)?;
                if let Some(update) = update {
                    self.expr(update)?;
                    self.discard_top()?;
                }
                self.emit_jump_to(condition_start)?;
                let loop_end = self.instructions.len();
                if let Some(exit_jump) = exit_jump {
                    self.patch_jump(exit_jump, loop_end)?;
                }
                self.patch_loop_breaks(loop_end)?;
                self.loops.pop();
                self.scopes.pop();
            }
            Statement::While { cond, block } => {
                let condition_start = self.instructions.len();
                self.expr(cond)?;
                let exit_jump = self.emit_jump_if_false();
                self.loops.push(LoopContext::default());
                self.block(block, true)?;
                self.patch_loop_continues(condition_start)?;
                self.emit_jump_to(condition_start)?;
                let loop_end = self.instructions.len();
                self.patch_jump(exit_jump, loop_end)?;
                self.patch_loop_breaks(loop_end)?;
                self.loops.pop();
            }
            Statement::DoWhile { block, cond } => {
                let body_start = self.instructions.len();
                self.loops.push(LoopContext::default());
                self.block(block, true)?;
                let condition_start = self.instructions.len();
                self.patch_loop_continues(condition_start)?;
                self.expr(cond)?;
                let exit_jump = self.emit_jump_if_false();
                self.emit_jump_to(body_start)?;
                let loop_end = self.instructions.len();
                self.patch_jump(exit_jump, loop_end)?;
                self.patch_loop_breaks(loop_end)?;
                self.loops.pop();
            }
            Statement::Break => {
                let jump = self.emit_jump();
                self.loops
                    .last_mut()
                    .expect("validator rejects break outside loops")
                    .breaks
                    .push(jump);
            }
            Statement::Continue => {
                let jump = self.emit_jump();
                self.loops
                    .last_mut()
                    .expect("validator rejects continue outside loops")
                    .continues
                    .push(jump);
            }
            Statement::Return(value) => {
                match (self.output, value) {
                    (Some(_), Some(value)) => {
                        self.expr(value)?;
                    }
                    (None, None) => {}
                    _ => return Err(unsupported("return does not match function output type")),
                }
                self.instructions.push(Instruction::Return);
            }
            Statement::Require { condition, .. } | Statement::Assert { condition, .. } => {
                self.expr(condition)?;
                let pass_jump = self.emit_jump_if_false();
                self.emit_jump_to(self.instructions.len() + 2)?;
                self.patch_jump(pass_jump, self.instructions.len())?;
                self.instructions.push(Instruction::Revert);
            }
            Statement::Block(block) => self.block(block, true)?,
            Statement::Revert { .. } => self.instructions.push(Instruction::Revert),
            Statement::Expression(expr) => {
                self.expr(expr)?;
                self.discard_top()?;
            }
            Statement::Emitevent { .. } | Statement::Placeholder => {
                return Err(unsupported(format!("statement {statement:?}")));
            }
        }
        Ok(())
    }

    fn expr(&mut self, expr: &Expr) -> Result<ValueType, CompileError> {
        match expr {
            Expr::LitInt(value) => {
                self.instructions.push(Instruction::Push(*value));
                Ok(ValueType::U64)
            }
            Expr::LitNumber(value) => {
                let normalized = value.trim().replace('_', "");
                let parsed = normalized
                    .strip_prefix("0x")
                    .or_else(|| normalized.strip_prefix("0X"))
                    .map_or_else(
                        || normalized.parse::<u64>(),
                        |hex| u64::from_str_radix(hex, 16),
                    )
                    .map_err(|_| unsupported(format!("integer literal {value}")))?;
                self.instructions.push(Instruction::Push(parsed));
                Ok(ValueType::U64)
            }
            Expr::LitBool(value) => {
                self.instructions.push(Instruction::Push(u64::from(*value)));
                Ok(ValueType::Bool)
            }
            Expr::Ident(name) => {
                let binding = self.lookup(name)?;
                let ty = binding.ty;
                self.load(binding);
                Ok(ty)
            }
            Expr::Add(left, right) => self.binary_u64(left, right, Instruction::Add),
            Expr::Sub(left, right) => self.binary_u64(left, right, Instruction::Sub),
            Expr::Mul(left, right) => self.binary_u64(left, right, Instruction::Mul),
            Expr::Div(left, right) => self.binary_u64(left, right, Instruction::Div),
            Expr::Mod(left, right) => self.binary_u64(left, right, Instruction::Mod),
            Expr::BitAnd(left, right) => self.binary_u64(left, right, Instruction::And),
            Expr::BitOr(left, right) => self.binary_u64(left, right, Instruction::Or),
            Expr::BitXor(left, right) => self.binary_u64(left, right, Instruction::BitXor),
            Expr::Shl(left, right) => self.binary_u64(left, right, Instruction::Shl),
            Expr::Shr(left, right) => self.binary_u64(left, right, Instruction::Shr),
            Expr::Eq(left, right) => self.binary_equal(left, right, false),
            Expr::Neq(left, right) => self.binary_equal(left, right, true),
            Expr::Lt(left, right) => self
                .binary_u64(left, right, Instruction::LessThan)
                .map(|_| ValueType::Bool),
            Expr::Gt(left, right) => self
                .binary_u64(left, right, Instruction::GreaterThan)
                .map(|_| ValueType::Bool),
            Expr::Gte(left, right) => {
                self.binary_u64(left, right, Instruction::LessThan)?;
                self.instructions.push(Instruction::Not);
                Ok(ValueType::Bool)
            }
            Expr::Lte(left, right) => {
                self.binary_u64(left, right, Instruction::GreaterThan)?;
                self.instructions.push(Instruction::Not);
                Ok(ValueType::Bool)
            }
            Expr::Not(inner) => {
                self.expr(inner)?;
                self.instructions.push(Instruction::Not);
                Ok(ValueType::Bool)
            }
            Expr::And(left, right) => self.logical_and(left, right),
            Expr::Or(left, right) => self.logical_or(left, right),
            Expr::Ternary {
                condition,
                true_expr,
                false_expr,
            } => {
                self.expr(condition)?;
                let false_jump = self.emit_jump_if_false();
                let ty = self.expr(true_expr)?;
                let end_jump = self.emit_jump();
                self.patch_jump(false_jump, self.instructions.len())?;
                self.expr(false_expr)?;
                self.patch_jump(end_jump, self.instructions.len())?;
                Ok(ty)
            }
            Expr::Assign { target, op, value } => self.assignment(target, op, value),
            Expr::Update {
                target,
                increment,
                prefix,
            } => self.update(target, *increment, *prefix),
            Expr::Call { func, args } if func == "ovm_authority_word" => {
                if self.argument_offset != AUTHORITY_WORD_COUNT || args.len() != 1 {
                    return Err(unsupported(
                        "`ovm_authority_word` is available only in deployed contract functions",
                    ));
                }
                let index = match &args[0] {
                    Expr::LitInt(index) => *index,
                    Expr::LitNumber(index) => {
                        let normalized = index.trim().replace('_', "");
                        normalized
                            .strip_prefix("0x")
                            .or_else(|| normalized.strip_prefix("0X"))
                            .map_or_else(
                                || normalized.parse::<u64>(),
                                |hex| u64::from_str_radix(hex, 16),
                            )
                            .map_err(|_| unsupported("invalid authority word index"))?
                    }
                    _ => return Err(unsupported("authority word index must be a literal")),
                };
                if index >= AUTHORITY_WORD_COUNT as u64 {
                    return Err(unsupported("authority word index must be from 0 through 3"));
                }
                self.instructions.push(Instruction::LoadArg(index as u8));
                Ok(ValueType::U64)
            }
            Expr::Call { func, args } if func == "poolSwap" => {
                if args.len() != 2 {
                    return Err(unsupported("`poolSwap` requires exactly two arguments"));
                }
                let pool_id_ty = self.expr(&args[0])?;
                let amount_ty = self.expr(&args[1])?;
                if pool_id_ty != ValueType::U64 || amount_ty != ValueType::U64 {
                    return Err(unsupported("`poolSwap` arguments must both be u64"));
                }
                self.instructions.push(Instruction::PoolSwap);
                Ok(ValueType::U64)
            }
            Expr::Address(addr) => {
                let value = u64::from_be_bytes(addr[12..20].try_into().expect("20-byte slice"));
                self.instructions.push(Instruction::Push(value));
                Ok(ValueType::Address)
            }
            Expr::Access { target, field } => {
                let binding = self.lookup(target)?;
                match &binding.kind {
                    BindingKind::Struct { struct_name } => {
                        let (field_ty, offset) = self.resolve_struct_field(struct_name, field)?;
                        let slot = binding.index + offset;
                        self.instructions.push(Instruction::LoadStorage(slot));
                        Ok(field_ty)
                    }
                    _ => Err(unsupported(format!(
                        "`{target}` is not a struct; cannot access field `{field}`"
                    ))),
                }
            }
            Expr::Index { target, index } => match target.as_ref() {
                Expr::Ident(name) => {
                    let binding = self.lookup(name)?;
                    match &binding.kind {
                        BindingKind::Mapping { value, .. } => {
                            self.instructions.push(Instruction::Push(binding.index));
                            self.expr(index)?;
                            self.instructions.push(Instruction::Hash { words: 2 });
                            self.instructions.push(Instruction::LoadStorageDyn);
                            Ok(*value)
                        }
                        _ => Err(unsupported(format!(
                            "`{name}` is not a mapping; cannot index"
                        ))),
                    }
                }
                _ => Err(unsupported("mapping index target must be a named variable")),
            },
            _ => Err(unsupported(format!("expression {expr:?}"))),
        }
    }

    fn binary_u64(
        &mut self,
        left: &Expr,
        right: &Expr,
        instruction: Instruction,
    ) -> Result<ValueType, CompileError> {
        self.expr(left)?;
        self.expr(right)?;
        self.instructions.push(instruction);
        Ok(ValueType::U64)
    }

    fn binary_equal(
        &mut self,
        left: &Expr,
        right: &Expr,
        negate: bool,
    ) -> Result<ValueType, CompileError> {
        self.expr(left)?;
        self.expr(right)?;
        self.instructions.push(Instruction::Equal);
        if negate {
            self.instructions.push(Instruction::Not);
        }
        Ok(ValueType::Bool)
    }

    fn logical_and(&mut self, left: &Expr, right: &Expr) -> Result<ValueType, CompileError> {
        self.expr(left)?;
        let false_left = self.emit_jump_if_false();
        self.expr(right)?;
        let false_right = self.emit_jump_if_false();
        self.instructions.push(Instruction::Push(1));
        let end_jump = self.emit_jump();
        let false_target = self.instructions.len();
        self.instructions.push(Instruction::Push(0));
        let end = self.instructions.len();
        self.patch_jump(false_left, false_target)?;
        self.patch_jump(false_right, false_target)?;
        self.patch_jump(end_jump, end)?;
        Ok(ValueType::Bool)
    }

    fn logical_or(&mut self, left: &Expr, right: &Expr) -> Result<ValueType, CompileError> {
        self.expr(left)?;
        let evaluate_right = self.emit_jump_if_false();
        self.instructions.push(Instruction::Push(1));
        let end_from_left = self.emit_jump();
        self.patch_jump(evaluate_right, self.instructions.len())?;
        self.expr(right)?;
        let false_right = self.emit_jump_if_false();
        self.instructions.push(Instruction::Push(1));
        let end_from_right = self.emit_jump();
        let false_target = self.instructions.len();
        self.instructions.push(Instruction::Push(0));
        let end = self.instructions.len();
        self.patch_jump(false_right, false_target)?;
        self.patch_jump(end_from_left, end)?;
        self.patch_jump(end_from_right, end)?;
        Ok(ValueType::Bool)
    }

    fn assignment(
        &mut self,
        target: &Expr,
        operator: &str,
        value: &Expr,
    ) -> Result<ValueType, CompileError> {
        match target {
            Expr::Index {
                target: inner,
                index: key,
            } => {
                let base = self.lvalue_ident_expr(inner)?;
                let (base_slot, (key_ty, value_ty)) = self.mapping_info(&base)?;
                if operator != "=" && value_ty != ValueType::U64 {
                    return Err(unsupported("compound assignment requires u64"));
                }
                if !matches!(operator, "=" | "+=" | "-=" | "*=" | "/=" | "%=") {
                    return Err(unsupported(format!("assignment operator `{operator}`")));
                }
                let _ = key_ty;
                if operator == "=" {
                    self.load_mapping_slot(&base_slot, key)?;
                    self.expr(value)?;
                    self.instructions.push(Instruction::StoreStorageDyn);
                } else {
                    self.load_mapping_slot(&base_slot, key)?;
                    let slot_temp = self.allocate_local()?;
                    self.instructions.push(Instruction::StoreLocal(slot_temp));
                    self.instructions.push(Instruction::LoadLocal(slot_temp));
                    self.instructions.push(Instruction::LoadStorageDyn);
                    self.expr(value)?;
                    self.instructions.push(match operator {
                        "+=" => Instruction::Add,
                        "-=" => Instruction::Sub,
                        "*=" => Instruction::Mul,
                        "/=" => Instruction::Div,
                        "%=" => Instruction::Mod,
                        _ => unreachable!(),
                    });
                    let val_temp = self.allocate_local()?;
                    self.instructions.push(Instruction::StoreLocal(val_temp));
                    self.instructions.push(Instruction::LoadLocal(slot_temp));
                    self.instructions.push(Instruction::LoadLocal(val_temp));
                    self.instructions.push(Instruction::StoreStorageDyn);
                }
                // Load the stored value back as the expression result
                self.load_mapping_slot(&base_slot, key)?;
                self.instructions.push(Instruction::LoadStorageDyn);
                Ok(value_ty)
            }
            Expr::Access { target, field } => {
                let binding = self.lookup(target)?;
                match &binding.kind {
                    BindingKind::Struct { struct_name } => {
                        let (field_ty, offset) = self.resolve_struct_field(struct_name, field)?;
                        let field_binding = Binding {
                            index: binding.index + offset,
                            ty: field_ty,
                            kind: BindingKind::Storage,
                        };
                        if operator != "=" && field_binding.ty != ValueType::U64 {
                            return Err(unsupported("compound assignment requires u64"));
                        }
                        if !matches!(operator, "=" | "+=" | "-=" | "*=" | "/=" | "%=") {
                            return Err(unsupported(format!("assignment operator `{operator}`")));
                        }
                        if operator != "=" {
                            self.load(field_binding.clone());
                            self.expr(value)?;
                            self.instructions.push(match operator {
                                "+=" => Instruction::Add,
                                "-=" => Instruction::Sub,
                                "*=" => Instruction::Mul,
                                "/=" => Instruction::Div,
                                "%=" => Instruction::Mod,
                                _ => unreachable!(),
                            });
                        } else {
                            self.expr(value)?;
                        }
                        self.store(field_binding.clone());
                        self.load(field_binding.clone());
                        Ok(field_binding.ty)
                    }
                    _ => Err(unsupported(format!(
                        "cannot access field `{field}` on non-struct"
                    ))),
                }
            }
            _ => {
                let binding = self.lvalue_expr(target)?;
                let ty = binding.ty;
                if operator != "=" && ty != ValueType::U64 {
                    return Err(unsupported("compound assignment requires u64"));
                }
                if !matches!(operator, "=" | "+=" | "-=" | "*=" | "/=" | "%=") {
                    return Err(unsupported(format!("assignment operator `{operator}`")));
                }
                if operator != "=" {
                    Self::expect(self.expr(target)?, ty, "compound assignment target")?;
                    self.load(binding.clone());
                    self.expr(value)?;
                    self.instructions.push(match operator {
                        "+=" => Instruction::Add,
                        "-=" => Instruction::Sub,
                        "*=" => Instruction::Mul,
                        "/=" => Instruction::Div,
                        "%=" => Instruction::Mod,
                        _ => unreachable!(),
                    });
                } else {
                    self.expr(value)?;
                }
                self.store(binding.clone());
                self.load(binding.clone());
                Ok(ty)
            }
        }
    }

    fn update(
        &mut self,
        target: &Expr,
        increment: bool,
        prefix: bool,
    ) -> Result<ValueType, CompileError> {
        match target {
            Expr::Index {
                target: inner,
                index: key,
            } => {
                let base = self.lvalue_ident_expr(inner)?;
                let (base_slot, (_key_ty, value_ty)) = self.mapping_info(&base)?;
                if value_ty != ValueType::U64 {
                    return Err(unsupported("increment/decrement requires u64"));
                }
                let temporary = if prefix {
                    None
                } else {
                    let temp = self.allocate_local()?;
                    self.load_mapping_slot(&base_slot, key)?;
                    self.instructions.push(Instruction::StoreLocal(temp));
                    Some(temp)
                };
                self.load_mapping_slot(&base_slot, key)?;
                self.instructions.push(Instruction::Push(1));
                self.instructions.push(if increment {
                    Instruction::Add
                } else {
                    Instruction::Sub
                });
                self.store_mapping_slot(&base_slot, key)?;
                if let Some(temp) = temporary {
                    self.instructions.push(Instruction::LoadLocal(temp));
                } else {
                    self.load_mapping_slot(&base_slot, key)?;
                }
                Ok(ValueType::U64)
            }
            _ => {
                let binding = self.lvalue_expr(target)?;
                Self::expect(binding.ty, ValueType::U64, "increment/decrement")?;
                let old_value = if prefix {
                    None
                } else {
                    let temporary = self.allocate_local()?;
                    self.load(binding.clone());
                    self.instructions.push(Instruction::StoreLocal(temporary));
                    Some(temporary)
                };
                self.load(binding.clone());
                self.instructions.push(Instruction::Push(1));
                self.instructions.push(if increment {
                    Instruction::Add
                } else {
                    Instruction::Sub
                });
                self.store(binding.clone());
                if let Some(temporary) = old_value {
                    self.instructions.push(Instruction::LoadLocal(temporary));
                } else {
                    self.load(binding.clone());
                }
                Ok(ValueType::U64)
            }
        }
    }

    /// Resolve an `&Expr` target that must be an `Expr::Ident` to a `Binding`.
    fn lvalue_ident_expr(&self, target: &Expr) -> Result<Binding, CompileError> {
        match target {
            Expr::Ident(name) => self.lookup(name),
            _ => Err(unsupported("mapping index target must be a named variable")),
        }
    }

    /// Resolve an `&LValue` target that must be an `LValue::Ident` to a `Binding`.
    fn lvalue_ident(&self, target: &LValue) -> Result<Binding, CompileError> {
        match target {
            LValue::Ident(name) => self.lookup(name),
            _ => Err(unsupported("mapping index base must be a named variable")),
        }
    }

    /// Extract (base_slot, key_type, value_type) from a mapping binding.
    fn mapping_info(
        &self,
        binding: &Binding,
    ) -> Result<(u64, (ValueType, ValueType)), CompileError> {
        match &binding.kind {
            BindingKind::Mapping { key, value } => Ok((binding.index, (*key, *value))),
            _ => Err(unsupported("target is not a mapping")),
        }
    }

    /// Emit instructions to compute a mapping slot: push base, eval key, Hash(2).
    fn load_mapping_slot(&mut self, base_slot: &u64, key: &Expr) -> Result<(), CompileError> {
        self.instructions.push(Instruction::Push(*base_slot));
        self.expr(key)?;
        self.instructions.push(Instruction::Hash { words: 2 });
        Ok(())
    }

    /// Emit StoreStorageDyn after the value is on the stack.
    fn store_mapping_slot(&mut self, base_slot: &u64, key: &Expr) -> Result<(), CompileError> {
        self.load_mapping_slot(base_slot, key)?;
        self.instructions.push(Instruction::StoreStorageDyn);
        Ok(())
    }

    fn lookup(&self, name: &str) -> Result<Binding, CompileError> {
        self.scopes
            .iter()
            .rev()
            .find_map(|scope| scope.get(name).cloned())
            .or_else(|| self.args.get(name).cloned())
            .or_else(|| self.storage.get(name).cloned())
            .ok_or_else(|| unsupported(format!("unknown identifier `{name}`")))
    }

    fn lvalue(&self, target: &LValue) -> Result<Binding, CompileError> {
        match target {
            LValue::Ident(name) => self.lookup(name),
            LValue::Member { base, field } => {
                let base_binding = self.lvalue(base)?;
                match &base_binding.kind {
                    BindingKind::Struct { struct_name } => {
                        let (field_ty, offset) = self.resolve_struct_field(struct_name, field)?;
                        Ok(Binding {
                            index: base_binding.index + offset,
                            ty: field_ty,
                            kind: BindingKind::Storage,
                        })
                    }
                    _ => Err(unsupported(format!(
                        "cannot access field `{field}` on non-struct"
                    ))),
                }
            }
            LValue::Index { .. } => Err(unsupported(
                "mapping index assignment is handled in statement",
            )),
        }
    }

    fn lvalue_expr(&self, target: &Expr) -> Result<Binding, CompileError> {
        match target {
            Expr::Ident(name) => self.lookup(name),
            Expr::Access { target, field } => {
                let binding = self.lookup(target)?;
                match &binding.kind {
                    BindingKind::Struct { struct_name } => {
                        let (field_ty, offset) = self.resolve_struct_field(struct_name, field)?;
                        Ok(Binding {
                            index: binding.index + offset,
                            ty: field_ty,
                            kind: BindingKind::Storage,
                        })
                    }
                    _ => Err(unsupported(format!(
                        "cannot access field `{field}` on non-struct"
                    ))),
                }
            }
            Expr::Index {
                target: inner,
                index: _,
            } => Err(unsupported(
                "mapping index assignment is handled in expression",
            )),
            _ => Err(unsupported("assignment target outside scalar variables")),
        }
    }

    /// Look up a field in a struct layout, returning (field_type, slot_offset).
    fn resolve_struct_field(
        &self,
        struct_name: &str,
        field: &str,
    ) -> Result<(ValueType, u64), CompileError> {
        self.struct_layouts
            .get(struct_name)
            .and_then(|fields| {
                fields
                    .iter()
                    .find(|(fname, _, _)| fname == field)
                    .map(|(_, ty, offset)| (*ty, *offset))
            })
            .ok_or_else(|| unsupported(format!("struct `{struct_name}` has no field `{field}`")))
    }

    fn load(&mut self, binding: Binding) {
        match binding.kind {
            BindingKind::Local => self
                .instructions
                .push(Instruction::LoadLocal(binding.index as u8)),
            BindingKind::Storage => self
                .instructions
                .push(Instruction::LoadStorage(binding.index)),
            BindingKind::Struct { .. } | BindingKind::Mapping { .. } => {
                // Structs and mappings are accessed only via member/index,
                // not as standalone values. This path should not be reached
                // if validation passed.
            }
        }
        if binding.ty == ValueType::Bool {
            self.normalize_boolean();
        }
    }

    fn store(&mut self, binding: Binding) {
        match binding.kind {
            BindingKind::Local => self
                .instructions
                .push(Instruction::StoreLocal(binding.index as u8)),
            BindingKind::Storage => self
                .instructions
                .push(Instruction::StoreStorage(binding.index)),
            BindingKind::Struct { .. } | BindingKind::Mapping { .. } => {
                // Structs and mappings are accessed only via member/index.
            }
        }
    }

    fn normalize_boolean(&mut self) {
        let false_jump = self.emit_jump_if_false();
        self.instructions.push(Instruction::Push(1));
        let end_jump = self.emit_jump();
        let false_target = self.instructions.len();
        self.instructions.push(Instruction::Push(0));
        let end = self.instructions.len();
        self.patch_jump(false_jump, false_target)
            .expect("compiler-generated boolean jump is valid");
        self.patch_jump(end_jump, end)
            .expect("compiler-generated boolean jump is valid");
    }

    fn allocate_local(&mut self) -> Result<u8, CompileError> {
        let index = self.local_count;
        self.local_count = self
            .local_count
            .checked_add(1)
            .ok_or_else(|| unsupported("too many local and temporary variables"))?;
        Ok(index)
    }

    fn expect(actual: ValueType, expected: ValueType, context: &str) -> Result<(), CompileError> {
        if actual == expected {
            Ok(())
        } else {
            Err(unsupported(format!(
                "{context} has type {actual:?}, expected {expected:?}"
            )))
        }
    }

    fn discard_top(&mut self) -> Result<(), CompileError> {
        let temporary = self.allocate_local()?;
        self.instructions.push(Instruction::StoreLocal(temporary));
        Ok(())
    }

    fn emit_jump(&mut self) -> usize {
        let index = self.instructions.len();
        self.instructions.push(Instruction::Jump(0));
        index
    }

    fn emit_jump_if_false(&mut self) -> usize {
        let index = self.instructions.len();
        self.instructions.push(Instruction::JumpIfFalse(0));
        index
    }

    fn emit_jump_to(&mut self, target: usize) -> Result<(), CompileError> {
        let jump = self.emit_jump();
        self.patch_jump(jump, target)
    }

    fn patch_jump(&mut self, instruction: usize, target: usize) -> Result<(), CompileError> {
        let target =
            u32::try_from(target).map_err(|_| unsupported("function exceeds jump range"))?;
        match self.instructions.get_mut(instruction) {
            Some(Instruction::Jump(value) | Instruction::JumpIfFalse(value)) => {
                *value = target;
                Ok(())
            }
            _ => Err(unsupported("invalid compiler jump")),
        }
    }

    fn patch_loop_continues(&mut self, target: usize) -> Result<(), CompileError> {
        let continues = std::mem::take(
            &mut self
                .loops
                .last_mut()
                .expect("loop context exists")
                .continues,
        );
        for jump in continues {
            self.patch_jump(jump, target)?;
        }
        Ok(())
    }

    fn patch_loop_breaks(&mut self, target: usize) -> Result<(), CompileError> {
        let breaks =
            std::mem::take(&mut self.loops.last_mut().expect("loop context exists").breaks);
        for jump in breaks {
            self.patch_jump(jump, target)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxydome_ovm::{execute, ExecutionFailure, Program, VmError};
    use std::collections::BTreeMap;

    fn run(source: &str, function: &str, args: &[u64], gas: u64) -> oxydome_ovm::Execution {
        let contract = crate::parse_contract(source).unwrap();
        let code = compile_function_to_ovm(&contract, function).unwrap();
        let program = Program::decode(&code).unwrap();
        execute(&program, args, &BTreeMap::new(), gas).unwrap()
    }

    fn run_error(source: &str, function: &str, args: &[u64], gas: u64) -> ExecutionFailure {
        let contract = crate::parse_contract(source).unwrap();
        let code = compile_function_to_ovm(&contract, function).unwrap();
        let program = Program::decode(&code).unwrap();
        execute(&program, args, &BTreeMap::new(), gas).unwrap_err()
    }

    #[test]
    fn compiles_scalar_values_and_boolean_outputs() {
        assert_eq!(
            run(
                "contract C { function add(uint64 a, uint64 b) public pure returns (uint64) { return a + b; } }",
                "add",
                &[12, 30],
                100,
            )
            .return_value,
            Some(42)
        );
        assert_eq!(
            run(
                "contract C { function yes(bool value) public pure returns (bool) { return value; } }",
                "yes",
                &[9],
                100,
            )
            .return_value,
            Some(1)
        );
        assert_eq!(
            run(
                "contract C { function yes(bool value) public pure returns (bool) { return value; } }",
                "yes",
                &[0],
                100,
            )
            .return_value,
            Some(0)
        );
        assert_eq!(
            run(
                "contract C { function update(uint64 value) public pure returns (uint64) { value++; return value; } }",
                "update",
                &[4],
                100,
            )
            .return_value,
            Some(5)
        );

        let contract = crate::parse_contract(
            "contract C { bool flag; function set(bool value) public returns (bool) { flag = value; return flag; } }",
        )
        .unwrap();
        let program = Program::decode(&compile_function_to_ovm(&contract, "set").unwrap()).unwrap();
        let stored = execute(&program, &[3], &BTreeMap::new(), 500).unwrap();
        assert_eq!(stored.return_value, Some(1));
        assert_eq!(stored.storage.get(&0), Some(&1));
    }

    #[test]
    fn lowers_comparisons_ternaries_and_short_circuit_logic() {
        let source = "contract C { uint64 count; function calc(uint64 a, bool b) public returns (uint64) { return a >= 2 && (b || (++count > 0)) ? 7 : 3; } }";
        let contract = crate::parse_contract(source).unwrap();
        let code = compile_function_to_ovm(&contract, "calc").unwrap();
        let program = Program::decode(&code).unwrap();
        let storage = BTreeMap::new();
        let skipped = execute(&program, &[3, 1], &storage, 500).unwrap();
        assert_eq!(skipped.return_value, Some(7));
        assert!(skipped.storage.is_empty());
        let executed = execute(&program, &[3, 0], &storage, 500).unwrap();
        assert_eq!(executed.return_value, Some(7));
        assert_eq!(executed.storage.get(&0), Some(&1));
        let skipped_and = execute(&program, &[1, 0], &storage, 500).unwrap();
        assert_eq!(skipped_and.return_value, Some(3));
        assert!(skipped_and.storage.is_empty());
    }

    #[test]
    fn supports_scoped_locals_assignments_updates_and_expression_statements() {
        let source = "contract C { function calc(uint64 start) public pure returns (uint64) { uint64 x = start; { uint64 x = 8; x++; } x += 2; x = x * 3; return x++; } }";
        assert_eq!(run(source, "calc", &[4], 1000).return_value, Some(18));
        let assigned =
            "contract C { function calc(uint64 start) public pure returns (uint64) { uint64 x = start; return (x = 9); } }";
        assert_eq!(run(assigned, "calc", &[4], 1000).return_value, Some(9));
        let returned_old =
            "contract C { function calc(uint64 start) public pure returns (uint64) { return start++; } }";
        assert_eq!(run(returned_old, "calc", &[4], 1000).return_value, Some(4));
    }

    #[test]
    fn implements_comparison_variants_and_keeps_bitwise_distinct() {
        for (expression, expected) in [
            ("2 != 3", 1),
            ("2 <= 2", 1),
            ("3 <= 2", 0),
            ("2 >= 2", 1),
            ("3 >= 4", 0),
        ] {
            let source = format!(
                "contract C {{ function compare() public pure returns (bool) {{ return {expression}; }} }}"
            );
            assert_eq!(
                run(&source, "compare", &[], 1000).return_value,
                Some(expected)
            );
        }
        assert_eq!(
            run(
                "contract C { function bits() public pure returns (uint64) { return 6 & 3; } }",
                "bits",
                &[],
                100,
            )
            .return_value,
            Some(2)
        );
        assert_eq!(
            run(
                "contract C { function noResult() public pure {} }",
                "noResult",
                &[],
                100,
            )
            .return_value,
            None
        );
    }

    #[test]
    fn lowers_for_while_do_while_and_nested_loop_control() {
        let source = "contract C { function sum() public pure returns (uint64) { uint64 total = 0; for (uint64 i = 0; i < 5; i++) { if (i == 2) continue; total += i; } uint64 j = 0; while (j < 3) { j++; if (j == 2) break; total += 10; } do { total++; } while (false); return total; } }";
        assert_eq!(run(source, "sum", &[], 5000).return_value, Some(19));
        let nested = "contract C { function count() public pure returns (uint64) { uint64 total = 0; for (uint64 i = 0; i < 3; i++) { for (uint64 j = 0; j < 3; j++) { if (j == 1) break; total++; } } return total; } }";
        assert_eq!(run(nested, "count", &[], 5000).return_value, Some(3));
    }

    #[test]
    fn preserves_checked_runtime_failures_and_gas() {
        let overflow = run_error(
            "contract C { function add(uint64 a) public pure returns (uint64) { return a + 1; } }",
            "add",
            &[u64::MAX],
            100,
        );
        assert_eq!(overflow.error, VmError::ArithmeticOverflow);
        assert_eq!(
            run_error(
                "contract C { function div(uint64 a) public pure returns (uint64) { return a / 0; } }",
                "div",
                &[4],
                100,
            )
            .error,
            VmError::DivisionByZero
        );
        assert_eq!(
            run_error(
                "contract C { function fail() public pure { require(false); } }",
                "fail",
                &[],
                100,
            )
            .error,
            VmError::Reverted
        );
        assert_eq!(
            run_error(
                "contract C { function loop() public pure { while (true) {} } }",
                "loop",
                &[],
                30,
            )
            .error,
            VmError::OutOfGas
        );
    }

    #[test]
    fn rejects_invalid_types_scopes_and_incomplete_return_paths() {
        for source in [
            "contract C { function f(uint256 value) public pure returns (uint64) { return 1; } }",
            "contract C { function f() public pure returns (uint64) { bool value = 1; return 1; } }",
            "contract C { function f() public pure returns (uint64) { uint64 x = 0; uint64 x = 1; return x; } }",
            "contract C { function f(bool condition) public pure returns (uint64) { if (condition) { return 1; } } }",
            "contract C { function f() public pure { break; } }",
            "contract C { function f() public pure { require(true, \"message\"); } }",
            "contract C { uint64 immutable value; function f() public { value = 1; } }",
            "contract C { function f() public pure returns (uint64) { return unknown; } }",
        ] {
            let contract = crate::parse_contract(source).unwrap();
            assert!(matches!(
                compile_function_to_ovm(&contract, "f"),
                Err(CompileError::Unsupported(_))
            ));
        }
    }

    #[test]
    fn compiles_public_functions_into_sorted_contract_artifact_with_authority_context() {
        let source = "contract C { uint64 value; function update(uint64 amount) public returns (uint64) { value += amount; return value; } function callerWord() external view returns (uint64) { return ovm_authority_word(0); } }";
        let contract = crate::parse_contract(source).unwrap();
        let encoded = compile_contract_to_ovm(&contract, None, None).unwrap();
        let artifact = ContractArtifact::decode(&encoded).unwrap();
        assert_eq!(
            artifact
                .functions
                .iter()
                .map(|function| function.name.as_str())
                .collect::<Vec<_>>(),
            vec!["callerWord", "update"]
        );

        let caller = artifact.function("callerWord").unwrap();
        let caller_program = Program::decode(&caller.code).unwrap();
        assert_eq!(caller_program.argument_count as usize, AUTHORITY_WORD_COUNT);
        assert_eq!(
            execute(&caller_program, &[17, 0, 0, 0], &BTreeMap::new(), 100)
                .unwrap()
                .return_value,
            Some(17)
        );

        let update = artifact.function("update").unwrap();
        let update_program = Program::decode(&update.code).unwrap();
        assert_eq!(
            update_program.argument_count as usize,
            AUTHORITY_WORD_COUNT + 1
        );
        let first = execute(&update_program, &[0, 0, 0, 0, 7], &BTreeMap::new(), 500).unwrap();
        let second = execute(&update_program, &[0, 0, 0, 0, 3], &first.storage, 500).unwrap();
        assert_eq!(first.return_value, Some(7));
        assert_eq!(second.return_value, Some(10));
    }

    #[test]
    fn rejects_authority_intrinsic_in_single_program_compilation() {
        let contract = crate::parse_contract(
            "contract C { function caller() public pure returns (uint64) { return ovm_authority_word(0); } }",
        )
        .unwrap();
        assert!(matches!(
            compile_function_to_ovm(&contract, "caller"),
            Err(CompileError::Unsupported(_))
        ));
    }

    #[test]
    fn compiles_address_literal_storage_and_retrieval() {
        let source = "contract C { address owner; function f() public returns (address) { owner = 0x000000000000000000000000000000000000002a; return owner; } }";
        assert_eq!(run(source, "f", &[], 1000).return_value, Some(42));
    }

    #[test]
    fn compiles_address_equality_and_inequality() {
        let source = "contract C { function eq(address a, address b) public pure returns (bool) { return a == b; } function ne(address a, address b) public pure returns (bool) { return a != b; } }";
        assert_eq!(run(source, "eq", &[42, 42], 1000).return_value, Some(1));
        assert_eq!(run(source, "eq", &[42, 99], 1000).return_value, Some(0));
        assert_eq!(run(source, "ne", &[42, 42], 1000).return_value, Some(0));
        assert_eq!(run(source, "ne", &[42, 99], 1000).return_value, Some(1));
    }

    #[test]
    fn rejects_address_arithmetic() {
        let source = "contract C { function f(address a, address b) public pure returns (uint64) { return a + b; } }";
        let contract = crate::parse_contract(source).unwrap();
        assert!(matches!(
            compile_function_to_ovm(&contract, "f"),
            Err(CompileError::Unsupported(_))
        ));
    }

    #[test]
    fn compiles_struct_member_read_write_from_storage() {
        let source = "contract C { struct Point { uint64 x; uint64 y; } Point position; function f() public returns (uint64) { position.x = 10; position.y = 20; return position.x + position.y; } }";
        assert_eq!(run(source, "f", &[], 1000).return_value, Some(30));
    }

    #[test]
    fn compiles_struct_member_persistence_across_calls() {
        let source = "contract C { struct Point { uint64 x; uint64 y; } Point position; function store() public { position.x = 7; position.y = 13; } function load() public returns (uint64) { return position.y - position.x; } }";
        let contract = crate::parse_contract(source).unwrap();
        let encoded = compile_contract_to_ovm(&contract, None, None).unwrap();
        let artifact = ContractArtifact::decode(&encoded).unwrap();
        let store_prog = Program::decode(&artifact.function("store").unwrap().code).unwrap();
        let load_prog = Program::decode(&artifact.function("load").unwrap().code).unwrap();
        let result = execute(&store_prog, &[0, 0, 0, 0], &BTreeMap::new(), 500).unwrap();
        let result2 = execute(&load_prog, &[0, 0, 0, 0], &result.storage, 500).unwrap();
        assert_eq!(result2.return_value, Some(6));
    }

    #[test]
    fn compiles_mapping_store_and_retrieve() {
        let source = "contract C { mapping(address => uint64) balances; function f() public returns (uint64) { balances[0x000000000000000000000000000000000000002a] = 42; return balances[0x000000000000000000000000000000000000002a]; } }";
        assert_eq!(run(source, "f", &[], 1000).return_value, Some(42));
    }

    #[test]
    fn compiles_mapping_different_keys_independent() {
        let source = "contract C { mapping(address => uint64) balances; function f() public returns (uint64) { balances[0x0000000000000000000000000000000000000001] = 10; balances[0x0000000000000000000000000000000000000002] = 20; return balances[0x0000000000000000000000000000000000000001]; } }";
        assert_eq!(run(source, "f", &[], 1000).return_value, Some(10));
    }

    #[test]
    fn compiles_full_contract_integration() {
        let source = "contract C { struct Point { uint64 x; uint64 y; } Point position; mapping(uint64 => uint64) balances; address owner; function f() public returns (uint64) { owner = 0x000000000000000000000000000000000000002a; position.x = 42; balances[position.x] = 99; if (owner == 0x000000000000000000000000000000000000002a) { return balances[position.x]; } return 0; } }";
        assert_eq!(run(source, "f", &[], 1000).return_value, Some(99));
    }
}
