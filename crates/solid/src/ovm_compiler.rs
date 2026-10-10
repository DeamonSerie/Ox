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
/// consensus-enforced DAO policy artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledSolid {
    pub contract_artifact: Vec<u8>,
    pub dao_policy: Option<Vec<u8>>,
}

pub fn compile_solid_to_ovm(
    contract: &Contract,
    source_hash: Option<oxydome_crypto::Hash>,
    asset_manifest_hash: Option<oxydome_crypto::Hash>,
) -> Result<CompiledSolid, CompileError> {
    Ok(CompiledSolid {
        contract_artifact: compile_contract_to_ovm(contract, source_hash, asset_manifest_hash)?,
        dao_policy: compile_dao_policy(contract)?,
    })
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

fn parse_fixed_hex<const N: usize>(value: &str) -> Result<[u8; N], String> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(value).map_err(|error| error.to_string())?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("expected {} bytes, received {}", N, bytes.len()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Binding {
    index: u64,
    ty: ValueType,
    kind: BindingKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BindingKind {
    Local,
    Storage,
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
            "more than {} scalar state variables",
            oxydome_ovm::MAX_STORAGE_SLOTS
        )));
    }
    let mut storage = BTreeMap::new();
    for (index, variable) in contract.variables.iter().enumerate() {
        storage.insert(
            variable.name.clone(),
            Binding {
                index: u64::try_from(index)
                    .map_err(|_| unsupported("too many scalar state variables"))?,
                ty: value_type(&variable.ty)?,
                kind: BindingKind::Storage,
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

fn value_type(ty: &Type) -> Result<ValueType, CompileError> {
    match ty {
        Type::U64 => Ok(ValueType::U64),
        Type::Bool => Ok(ValueType::Bool),
        _ => Err(unsupported(format!("type {ty:?}"))),
    }
}

fn artifact_type(ty: &Type) -> Result<ContractValueType, CompileError> {
    match value_type(ty)? {
        ValueType::U64 => Ok(ContractValueType::U64),
        ValueType::Bool => Ok(ContractValueType::Bool),
    }
}

fn unsupported(message: impl Into<String>) -> CompileError {
    CompileError::Unsupported(message.into())
}

struct FunctionCompiler {
    instructions: Vec<Instruction>,
    args: BTreeMap<String, Binding>,
    storage: BTreeMap<String, Binding>,
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
            Statement::Assign { target, value } => {
                self.expr(value)?;
                let binding = self.lvalue(target)?;
                self.store(binding);
            }
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
                self.load(binding);
                Ok(binding.ty)
            }
            Expr::Add(left, right) => self.binary_u64(left, right, Instruction::Add),
            Expr::Sub(left, right) => self.binary_u64(left, right, Instruction::Sub),
            Expr::Mul(left, right) => self.binary_u64(left, right, Instruction::Mul),
            Expr::Div(left, right) => self.binary_u64(left, right, Instruction::Div),
            Expr::Mod(left, right) => self.binary_u64(left, right, Instruction::Mod),
            Expr::BitAnd(left, right) => self.binary_u64(left, right, Instruction::And),
            Expr::BitOr(left, right) => self.binary_u64(left, right, Instruction::Or),
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
        let binding = self.lvalue_expr(target)?;
        if operator == "=" {
            self.expr(value)?;
        } else {
            self.load(binding);
            self.expr(value)?;
            self.instructions.push(match operator {
                "+=" => Instruction::Add,
                "-=" => Instruction::Sub,
                "*=" => Instruction::Mul,
                "/=" => Instruction::Div,
                "%=" => Instruction::Mod,
                _ => return Err(unsupported(format!("assignment operator `{operator}`"))),
            });
        }
        self.store(binding);
        self.load(binding);
        Ok(binding.ty)
    }

    fn update(
        &mut self,
        target: &Expr,
        increment: bool,
        prefix: bool,
    ) -> Result<ValueType, CompileError> {
        let binding = self.lvalue_expr(target)?;
        let old_value = if prefix {
            None
        } else {
            let temporary = self.allocate_local()?;
            self.load(binding);
            self.instructions.push(Instruction::StoreLocal(temporary));
            Some(temporary)
        };
        self.load(binding);
        self.instructions.push(Instruction::Push(1));
        self.instructions.push(if increment {
            Instruction::Add
        } else {
            Instruction::Sub
        });
        self.store(binding);
        if let Some(temporary) = old_value {
            self.instructions.push(Instruction::LoadLocal(temporary));
        } else {
            self.load(binding);
        }
        Ok(ValueType::U64)
    }

    fn lookup(&self, name: &str) -> Result<Binding, CompileError> {
        self.scopes
            .iter()
            .rev()
            .find_map(|scope| scope.get(name).copied())
            .or_else(|| self.args.get(name).copied())
            .or_else(|| self.storage.get(name).copied())
            .ok_or_else(|| unsupported(format!("unknown identifier `{name}`")))
    }

    fn lvalue(&self, target: &LValue) -> Result<Binding, CompileError> {
        match target {
            LValue::Ident(name) => self.lookup(name),
            _ => Err(unsupported("assignment target outside scalar variables")),
        }
    }

    fn lvalue_expr(&self, target: &Expr) -> Result<Binding, CompileError> {
        match target {
            Expr::Ident(name) => self.lookup(name),
            _ => Err(unsupported("assignment target outside scalar variables")),
        }
    }

    fn load(&mut self, binding: Binding) {
        match binding.kind {
            BindingKind::Local => self
                .instructions
                .push(Instruction::LoadLocal(binding.index as u8)),
            BindingKind::Storage => self
                .instructions
                .push(Instruction::LoadStorage(binding.index)),
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
}
