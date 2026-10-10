use crate::ast::{
    Block, Contract, ContractKind, Expr, Function, FunctionKind, LValue, Statement, Type,
};
use crate::CompileError;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ValueType {
    U64,
    Bool,
}

impl ValueType {
    fn from_solid(ty: &Type) -> Result<Self, CompileError> {
        match ty {
            Type::U64 => Ok(Self::U64),
            Type::Bool => Ok(Self::Bool),
            _ => Err(unsupported(format!("type {ty:?}"))),
        }
    }
}

pub(crate) fn validate_function(
    contract: &Contract,
    function: &Function,
) -> Result<(), CompileError> {
    validate_function_with_context(contract, function, false)
}

pub(crate) fn validate_function_with_context(
    contract: &Contract,
    function: &Function,
    authority_context: bool,
) -> Result<(), CompileError> {
    if contract.kind != ContractKind::Contract {
        return Err(unsupported(
            "only contract definitions can be compiled to OVM",
        ));
    }
    if !contract.parents.is_empty() {
        return Err(unsupported("inheritance"));
    }
    if contract
        .variables
        .iter()
        .any(|variable| variable.initializer.is_some())
    {
        return Err(unsupported("state variable initializers"));
    }
    if contract
        .functions
        .iter()
        .filter(|candidate| candidate.name == function.name)
        .count()
        > 1
    {
        return Err(unsupported(format!(
            "overloaded function `{}`",
            function.name
        )));
    }
    if function.kind != FunctionKind::Function {
        return Err(unsupported("constructors and special functions"));
    }
    if !function.modifiers.is_empty() {
        return Err(unsupported("function modifiers"));
    }
    let argument_limit = oxydome_core::MAX_OVM_ARGUMENTS
        - if authority_context {
            oxydome_ovm::AUTHORITY_WORD_COUNT
        } else {
            0
        };
    if function.inputs.len() > argument_limit {
        return Err(unsupported(format!(
            "more than {argument_limit} parameters for this OVM call context"
        )));
    }
    if function.outputs.len() > 1 {
        return Err(unsupported("multiple return values"));
    }

    let mut state = BTreeMap::new();
    for variable in &contract.variables {
        let ty = ValueType::from_solid(&variable.ty)?;
        if variable.constant || variable.immutable {
            return Err(unsupported(format!(
                "constant or immutable state variable `{}`",
                variable.name
            )));
        }
        if state
            .insert(variable.name.clone(), (ty, variable.mutable))
            .is_some()
        {
            return Err(unsupported(format!(
                "duplicate state variable `{}`",
                variable.name
            )));
        }
    }

    let output = function
        .outputs
        .first()
        .map(|param| ValueType::from_solid(&param.ty))
        .transpose()?;
    let mut checker = Checker {
        state,
        scopes: vec![BTreeMap::new()],
        output,
        loop_depth: 0,
        authority_context,
    };
    for param in &function.inputs {
        let ty = ValueType::from_solid(&param.ty)?;
        if !param.name.is_empty() {
            checker.declare(param.name.clone(), ty)?;
        }
    }
    checker.block(&function.body, false)?;
    if output.is_some() && !always_returns(&function.body) {
        return Err(unsupported(
            "not all control-flow paths return the declared value",
        ));
    }
    Ok(())
}

fn always_returns(block: &Block) -> bool {
    block.statements.iter().any(|statement| match statement {
        Statement::Return(_) | Statement::Revert { .. } => true,
        Statement::Block(block) => always_returns(block),
        Statement::If {
            true_block,
            false_block: Some(false_block),
            ..
        } => always_returns(true_block) && always_returns(false_block),
        _ => false,
    })
}

struct Checker {
    state: BTreeMap<String, (ValueType, bool)>,
    scopes: Vec<BTreeMap<String, ValueType>>,
    output: Option<ValueType>,
    loop_depth: usize,
    authority_context: bool,
}

impl Checker {
    fn declare(&mut self, name: String, ty: ValueType) -> Result<(), CompileError> {
        let scope = self.scopes.last_mut().expect("function scope exists");
        if scope.insert(name.clone(), ty).is_some() {
            return Err(unsupported(format!("duplicate declaration `{name}`")));
        }
        Ok(())
    }

    fn lookup(&self, name: &str) -> Option<ValueType> {
        self.scopes
            .iter()
            .rev()
            .find_map(|scope| scope.get(name).copied())
            .or_else(|| self.state.get(name).map(|(ty, _)| *ty))
    }

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
                let ty = ValueType::from_solid(ty)?;
                if let Some(init) = init {
                    Self::expect(self.expr(init)?, ty, "local initializer")?;
                }
                self.declare(name.clone(), ty)
            }
            Statement::Assign { target, value } => {
                let target = self.lvalue(target, true)?;
                Self::expect(self.expr(value)?, target, "assignment")?;
                Ok(())
            }
            Statement::If {
                condition,
                true_block,
                false_block,
            } => {
                Self::expect(self.expr(condition)?, ValueType::Bool, "if condition")?;
                self.block(true_block, true)?;
                if let Some(block) = false_block {
                    self.block(block, true)?;
                }
                Ok(())
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
                if let Some(cond) = cond {
                    Self::expect(self.expr(cond)?, ValueType::Bool, "for condition")?;
                }
                if let Some(update) = update {
                    self.expr(update)?;
                }
                self.loop_depth += 1;
                self.block(block, true)?;
                self.loop_depth -= 1;
                self.scopes.pop();
                Ok(())
            }
            Statement::While { cond, block } => {
                Self::expect(self.expr(cond)?, ValueType::Bool, "while condition")?;
                self.loop_depth += 1;
                self.block(block, true)?;
                self.loop_depth -= 1;
                Ok(())
            }
            Statement::DoWhile { block, cond } => {
                self.loop_depth += 1;
                self.block(block, true)?;
                self.loop_depth -= 1;
                Self::expect(self.expr(cond)?, ValueType::Bool, "do/while condition")
            }
            Statement::Break | Statement::Continue if self.loop_depth == 0 => {
                Err(unsupported("break/continue outside a loop"))
            }
            Statement::Break | Statement::Continue => Ok(()),
            Statement::Return(value) => match (self.output, value) {
                (None, None) => Ok(()),
                (Some(expected), Some(value)) => {
                    Self::expect(self.expr(value)?, expected, "return value")
                }
                (None, Some(_)) => Err(unsupported("return value from a void function")),
                (Some(_), None) => Err(unsupported("missing return value")),
            },
            Statement::Require { condition, message } => {
                if message.is_some() {
                    return Err(unsupported("require revert messages"));
                }
                Self::expect(
                    self.expr(condition)?,
                    ValueType::Bool,
                    "require/assert condition",
                )
            }
            Statement::Assert { condition, message } => {
                if !message.is_empty() {
                    return Err(unsupported("assert revert messages"));
                }
                Self::expect(
                    self.expr(condition)?,
                    ValueType::Bool,
                    "require/assert condition",
                )
            }
            Statement::Revert { error: None, args } if args.is_empty() => Ok(()),
            Statement::Revert { .. } => Err(unsupported("custom errors and revert data")),
            Statement::Block(block) => self.block(block, true),
            Statement::Expression(expr) => {
                self.expr(expr)?;
                Ok(())
            }
            Statement::Emitevent { .. } => Err(unsupported("event emission")),
            Statement::Placeholder => Err(unsupported("modifier placeholders")),
        }
    }

    fn expr(&mut self, expr: &Expr) -> Result<ValueType, CompileError> {
        match expr {
            Expr::LitInt(_) | Expr::LitNumber(_) => Ok(ValueType::U64),
            Expr::LitBool(_) => Ok(ValueType::Bool),
            Expr::Ident(name) => self
                .lookup(name)
                .ok_or_else(|| unsupported(format!("unknown identifier `{name}`"))),
            Expr::Add(lhs, rhs)
            | Expr::Sub(lhs, rhs)
            | Expr::Mul(lhs, rhs)
            | Expr::Div(lhs, rhs)
            | Expr::Mod(lhs, rhs)
            | Expr::BitAnd(lhs, rhs)
            | Expr::BitOr(lhs, rhs) => {
                Self::expect(self.expr(lhs)?, ValueType::U64, "left arithmetic operand")?;
                Self::expect(self.expr(rhs)?, ValueType::U64, "right arithmetic operand")?;
                Ok(ValueType::U64)
            }
            Expr::Eq(lhs, rhs) | Expr::Neq(lhs, rhs) => {
                let lhs_type = self.expr(lhs)?;
                Self::expect(self.expr(rhs)?, lhs_type, "equality operands")?;
                Ok(ValueType::Bool)
            }
            Expr::Gt(lhs, rhs) | Expr::Lt(lhs, rhs) | Expr::Gte(lhs, rhs) | Expr::Lte(lhs, rhs) => {
                Self::expect(self.expr(lhs)?, ValueType::U64, "comparison operand")?;
                Self::expect(self.expr(rhs)?, ValueType::U64, "comparison operand")?;
                Ok(ValueType::Bool)
            }
            Expr::Not(value) => {
                Self::expect(self.expr(value)?, ValueType::Bool, "logical not operand")?;
                Ok(ValueType::Bool)
            }
            Expr::And(lhs, rhs) | Expr::Or(lhs, rhs) => {
                Self::expect(self.expr(lhs)?, ValueType::Bool, "logical operand")?;
                Self::expect(self.expr(rhs)?, ValueType::Bool, "logical operand")?;
                Ok(ValueType::Bool)
            }
            Expr::Ternary {
                condition,
                true_expr,
                false_expr,
            } => {
                Self::expect(self.expr(condition)?, ValueType::Bool, "ternary condition")?;
                let true_type = self.expr(true_expr)?;
                Self::expect(self.expr(false_expr)?, true_type, "ternary branches")?;
                Ok(true_type)
            }
            Expr::Assign { target, op, value } => {
                let ty = self.lvalue_expr(target)?;
                if op != "=" && ty != ValueType::U64 {
                    return Err(unsupported("compound assignment requires u64"));
                }
                if !matches!(op.as_str(), "=" | "+=" | "-=" | "*=" | "/=" | "%=") {
                    return Err(unsupported(format!("assignment operator `{op}`")));
                }
                if op != "=" {
                    Self::expect(self.expr(target)?, ty, "compound assignment target")?;
                }
                Self::expect(self.expr(value)?, ty, "assignment")?;
                Ok(ty)
            }
            Expr::Update { target, .. } => {
                Self::expect(
                    self.lvalue_expr(target)?,
                    ValueType::U64,
                    "increment/decrement",
                )?;
                Ok(ValueType::U64)
            }
            Expr::Call { func, args } if func == "ovm_authority_word" => {
                if !self.authority_context {
                    return Err(unsupported(
                        "`ovm_authority_word` is available only in deployed contract functions",
                    ));
                }
                match args.as_slice() {
                    [Expr::LitInt(index)] if *index < oxydome_ovm::AUTHORITY_WORD_COUNT as u64 => {
                        Ok(ValueType::U64)
                    }
                    [Expr::LitNumber(index)]
                        if parse_u64_literal(index).is_some_and(|index| {
                            index < oxydome_ovm::AUTHORITY_WORD_COUNT as u64
                        }) =>
                    {
                        Ok(ValueType::U64)
                    }
                    _ => Err(unsupported(
                        "`ovm_authority_word` requires one literal index from 0 through 3",
                    )),
                }
            }
            Expr::Call { func, .. } if func == "require" || func == "assert" => {
                Err(unsupported(format!("statement-only `{func}`")))
            }
            Expr::Call { func, .. } => Err(unsupported(format!("function call `{func}`"))),
            Expr::Access { target, field } => Err(unsupported(format!(
                "member access `{target}.{field}` has no native OVM meaning"
            ))),
            Expr::Index { .. } => Err(unsupported("array and mapping indexing")),
            Expr::UMinus(_) => Err(unsupported("signed arithmetic")),
            Expr::LitDecimal(_) => Err(unsupported("decimal literals")),
            Expr::LitString(_) => Err(unsupported("string values")),
            Expr::Address(_) => Err(unsupported("address values")),
            Expr::Pow(_, _) => Err(unsupported("exponentiation")),
            Expr::BitXor(_, _) => Err(unsupported("bitwise XOR")),
            Expr::Shl(_, _) | Expr::Shr(_, _) => Err(unsupported("bit shifts")),
        }
    }

    fn lvalue(&mut self, target: &LValue, write: bool) -> Result<ValueType, CompileError> {
        match target {
            LValue::Ident(name) => {
                if let Some(ty) = self
                    .scopes
                    .iter()
                    .rev()
                    .find_map(|scope| scope.get(name).copied())
                {
                    return Ok(ty);
                }
                match self.state.get(name) {
                    Some((ty, mutable)) if !write || *mutable => Ok(*ty),
                    Some(_) => Err(unsupported(format!(
                        "assignment to immutable state `{name}`"
                    ))),
                    None => Err(unsupported(format!("unknown assignment target `{name}`"))),
                }
            }
            LValue::Index { .. } => Err(unsupported("array and mapping indexing")),
            LValue::Member { .. } => Err(unsupported("member assignment")),
        }
    }

    fn lvalue_expr(&mut self, target: &Expr) -> Result<ValueType, CompileError> {
        match target {
            Expr::Ident(name) => self.lvalue(&LValue::Ident(name.clone()), true),
            Expr::Index { .. } => Err(unsupported("array and mapping indexing")),
            Expr::Access { .. } => Err(unsupported("member assignment")),
            _ => Err(unsupported("non-variable assignment target")),
        }
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
}

fn unsupported(message: impl Into<String>) -> CompileError {
    CompileError::Unsupported(message.into())
}

fn parse_u64_literal(value: &str) -> Option<u64> {
    let value = value.trim().replace('_', "");
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map_or_else(
            || value.parse().ok(),
            |hex| u64::from_str_radix(hex, 16).ok(),
        )
}
