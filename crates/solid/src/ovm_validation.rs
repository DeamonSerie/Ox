use crate::ast::{
    Block, Contract, ContractKind, Expr, Function, FunctionKind, LValue, Statement, Type,
};
use crate::CompileError;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ValueType {
    U64,
    Bool,
    Address,
}

impl ValueType {
    pub(crate) fn from_solid(ty: &Type) -> Result<Self, CompileError> {
        match ty {
            Type::U64 => Ok(Self::U64),
            Type::Bool => Ok(Self::Bool),
            Type::Address => Ok(Self::Address),
            _ => Err(unsupported(format!("type {ty:?}"))),
        }
    }
}

/// How a state variable is represented in storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StateKind {
    Scalar(ValueType),
    Struct(String),
    Mapping { key: ValueType, value: ValueType },
}

/// Extracted mapping key/value types (returned by helpers to avoid using a variant as a type).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MappingInfo {
    pub key: ValueType,
    pub value: ValueType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StateVar {
    pub kind: StateKind,
    pub mutable: bool,
}

impl StateVar {
    pub fn mapping_info(&self) -> Option<MappingInfo> {
        match self.kind {
            StateKind::Mapping { key, value } => Some(MappingInfo { key, value }),
            _ => None,
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

    let struct_layouts = build_struct_layouts(contract)?;

    let mut state = BTreeMap::new();
    for variable in &contract.variables {
        let kind = state_var_kind(&variable.ty, &struct_layouts)?;
        if variable.constant || variable.immutable {
            return Err(unsupported(format!(
                "constant or immutable state variable `{}`",
                variable.name
            )));
        }
        if state
            .insert(
                variable.name.clone(),
                StateVar {
                    kind,
                    mutable: variable.mutable,
                },
            )
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
        struct_layouts,
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

/// Build a lookup from struct name to its field list (name, type).
/// Only `u64`/`bool`/`address` field types are supported.
fn build_struct_layouts(
    contract: &Contract,
) -> Result<BTreeMap<String, Vec<(String, ValueType)>>, CompileError> {
    let mut layouts = BTreeMap::new();
    for struct_def in &contract.structs {
        let mut fields = Vec::new();
        let mut seen = BTreeMap::new();
        for field in &struct_def.fields {
            let ty = ValueType::from_solid(&field.ty).map_err(|_| {
                unsupported(format!(
                    "struct `{}` field `{}` has unsupported type {:?}",
                    struct_def.name, field.name, field.ty
                ))
            })?;
            if seen.insert(field.name.clone(), ()).is_some() {
                return Err(unsupported(format!(
                    "duplicate field `{}` in struct `{}`",
                    field.name, struct_def.name
                )));
            }
            fields.push((field.name.clone(), ty));
        }
        layouts.insert(struct_def.name.clone(), fields);
    }
    Ok(layouts)
}

/// Resolve a `Type` into a `StateKind` for a state variable.
fn state_var_kind(
    ty: &Type,
    struct_layouts: &BTreeMap<String, Vec<(String, ValueType)>>,
) -> Result<StateKind, CompileError> {
    match ty {
        Type::Named(name) => {
            if struct_layouts.contains_key(name) {
                Ok(StateKind::Struct(name.clone()))
            } else {
                Err(unsupported(format!("unknown named type `{name}`")))
            }
        }
        Type::Mapping { key, value } => {
            let key_ty = ValueType::from_solid(key)
                .map_err(|_| unsupported(format!("mapping key type {:?} is not supported", key)))?;
            // The value type of a mapping can itself be a struct or scalar.
            let value_kind = state_var_kind(value, struct_layouts)?;
            match value_kind {
                StateKind::Scalar(ty) => Ok(StateKind::Mapping {
                    key: key_ty,
                    value: ty,
                }),
                StateKind::Struct(name) => Err(unsupported(format!(
                    "mapping value type struct `{name}` is not yet supported"
                ))),
                StateKind::Mapping { .. } => Err(unsupported(
                    "nested mappings as mapping values are not yet supported",
                )),
            }
        }
        _ => ValueType::from_solid(ty).map(StateKind::Scalar),
    }
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
    state: BTreeMap<String, StateVar>,
    struct_layouts: BTreeMap<String, Vec<(String, ValueType)>>,
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
            .or_else(|| match self.state.get(name) {
                Some(StateVar {
                    kind: StateKind::Scalar(ty),
                    ..
                }) => Some(*ty),
                _ => None,
            })
    }

    /// Look up a state variable (not a local/arg) and return its `StateKind`.
    fn lookup_state(&self, name: &str) -> Option<StateKind> {
        self.state.get(name).map(|var| var.kind.clone())
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
            Expr::Address(_) => Ok(ValueType::Address),
            Expr::Ident(name) => self
                .lookup(name)
                .ok_or_else(|| unsupported(format!("unknown identifier `{name}`"))),
            Expr::Add(lhs, rhs)
            | Expr::Sub(lhs, rhs)
            | Expr::Mul(lhs, rhs)
            | Expr::Div(lhs, rhs)
            | Expr::Mod(lhs, rhs)
            | Expr::BitAnd(lhs, rhs) => {
                Self::expect(self.expr(lhs)?, ValueType::U64, "left arithmetic operand")?;
                Self::expect(self.expr(rhs)?, ValueType::U64, "right arithmetic operand")?;
                Ok(ValueType::U64)
            }
            Expr::BitOr(lhs, rhs) => {
                Self::expect(self.expr(lhs)?, ValueType::U64, "left arithmetic operand")?;
                Self::expect(self.expr(rhs)?, ValueType::U64, "right arithmetic operand")?;
                Ok(ValueType::U64)
            }
            Expr::BitXor(lhs, rhs) => {
                Self::expect(self.expr(lhs)?, ValueType::U64, "left arithmetic operand")?;
                Self::expect(self.expr(rhs)?, ValueType::U64, "right arithmetic operand")?;
                Ok(ValueType::U64)
            }
            Expr::Shl(lhs, rhs) => {
                Self::expect(self.expr(lhs)?, ValueType::U64, "left shift operand")?;
                Self::expect(self.expr(rhs)?, ValueType::U64, "right shift operand")?;
                Ok(ValueType::U64)
            }
            Expr::Shr(lhs, rhs) => {
                Self::expect(self.expr(lhs)?, ValueType::U64, "left shift operand")?;
                Self::expect(self.expr(rhs)?, ValueType::U64, "right shift operand")?;
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
            Expr::Call { func, args } if func == "poolSwap" => {
                if args.len() != 2 {
                    return Err(unsupported("`poolSwap` requires exactly two arguments"));
                }
                let pool_id_ty = self.expr(&args[0])?;
                let amount_ty = self.expr(&args[1])?;
                if pool_id_ty != ValueType::U64 || amount_ty != ValueType::U64 {
                    return Err(unsupported("`poolSwap` arguments must both be u64"));
                }
                Ok(ValueType::U64)
            }
            Expr::Call { func, .. } if func == "require" || func == "assert" => {
                Err(unsupported(format!("statement-only `{func}`")))
            }
            Expr::Call { func, .. } => Err(unsupported(format!("function call `{func}`"))),
            Expr::Access { target, field } => {
                let struct_name = match self.lookup_state(target) {
                    Some(StateKind::Struct(name)) => name,
                    Some(_) => {
                        return Err(unsupported(format!(
                            "`{target}` is not a struct; member access requires a struct"
                        )));
                    }
                    None => {
                        // Could be a local variable that is a struct — but
                        // structs can only be state variables in OVM.
                        return Err(unsupported(format!("unknown identifier `{target}`")));
                    }
                };
                self.resolve_struct_field(&struct_name, field)
            }
            Expr::Index { target, index } => {
                let mapping = self.lvalue_index_expr(target)?;
                let key_ty = self.expr(index)?;
                Self::expect(key_ty, mapping.key, "mapping key")?;
                Ok(mapping.value)
            }
            Expr::LitDecimal(_) => Err(unsupported("decimal literals")),
            Expr::LitString(_) => Err(unsupported("string values")),
            Expr::UMinus(_) => Err(unsupported("signed arithmetic")),
            Expr::Pow(_, _) => Err(unsupported("exponentiation")),
        }
    }

    fn lvalue(&mut self, target: &LValue, write: bool) -> Result<ValueType, CompileError> {
        match target {
            LValue::Ident(name) => {
                let ty = self
                    .scopes
                    .iter()
                    .rev()
                    .find_map(|scope| scope.get(name).copied());
                if let Some(ty) = ty {
                    return Ok(ty);
                }
                match self.state.get(name) {
                    Some(StateVar {
                        kind: StateKind::Scalar(ty),
                        mutable,
                    }) if !write || *mutable => Ok(*ty),
                    Some(_) => Err(unsupported(format!(
                        "assignment to immutable state `{name}`"
                    ))),
                    None => Err(unsupported(format!("unknown assignment target `{name}`"))),
                }
            }
            LValue::Index { base, index } => {
                let mapping = self.lvalue_mapping_base(base, write)?;
                let key_ty = self.expr(index)?;
                Self::expect(key_ty, mapping.key, "mapping key")?;
                Ok(mapping.value)
            }
            LValue::Member { base, field } => {
                let struct_name = self.lvalue_struct_base(base, write)?;
                let field_ty = self.resolve_struct_field(&struct_name, field)?;
                Ok(field_ty)
            }
        }
    }

    /// Resolve an `LValue` base for mapping indexing: must evaluate to a
    /// `Mapping` state variable.
    fn lvalue_mapping_base(
        &mut self,
        base: &LValue,
        write: bool,
    ) -> Result<MappingInfo, CompileError> {
        match base {
            LValue::Ident(name) => match self.lookup_state(name) {
                Some(StateKind::Mapping { key, value }) => {
                    if write {
                        if let Some(var) = self.state.get(name) {
                            if !var.mutable {
                                return Err(unsupported(format!(
                                    "assignment to immutable state `{name}`"
                                )));
                            }
                        }
                    }
                    Ok(MappingInfo { key, value })
                }
                Some(_) => Err(unsupported(format!(
                    "`{name}` is not a mapping; indexing requires a mapping"
                ))),
                None => Err(unsupported(format!("unknown assignment target `{name}`"))),
            },
            _ => Err(unsupported("mapping index base must be a named variable")),
        }
    }

    /// Resolve an `LValue` base for struct member access: must evaluate to a
    /// `Struct` state variable, returning its struct name.
    fn lvalue_struct_base(&mut self, base: &LValue, write: bool) -> Result<String, CompileError> {
        match base {
            LValue::Ident(name) => match self.lookup_state(name) {
                Some(StateKind::Struct(struct_name)) => {
                    if write {
                        if let Some(var) = self.state.get(name) {
                            if !var.mutable {
                                return Err(unsupported(format!(
                                    "assignment to immutable state `{name}`"
                                )));
                            }
                        }
                    }
                    Ok(struct_name)
                }
                Some(_) => Err(unsupported(format!(
                    "`{name}` is not a struct; member access requires a struct"
                ))),
                None => Err(unsupported(format!("unknown assignment target `{name}`"))),
            },
            LValue::Member { base: inner, field } => {
                let parent = self.lvalue_struct_base(inner, write)?;
                let _ = self.resolve_struct_field(&parent, field)?;
                // For now, nested struct member access is not supported (field would
                // need to be a struct type, but ValueType doesn't carry struct names).
                Err(unsupported(
                    "nested struct member assignment is not supported",
                ))
            }
            _ => Err(unsupported("struct member base must be a named variable")),
        }
    }

    /// Look up a field in a struct layout and return its `ValueType`.
    fn resolve_struct_field(
        &self,
        struct_name: &str,
        field: &str,
    ) -> Result<ValueType, CompileError> {
        match self.struct_layouts.get(struct_name) {
            Some(fields) => fields
                .iter()
                .find(|(fname, _)| fname == field)
                .map(|(_, ty)| *ty)
                .ok_or_else(|| {
                    unsupported(format!("struct `{struct_name}` has no field `{field}`"))
                }),
            None => Err(unsupported(format!("unknown struct `{struct_name}`"))),
        }
    }

    fn lvalue_expr(&mut self, target: &Expr) -> Result<ValueType, CompileError> {
        match target {
            Expr::Ident(name) => self.lvalue(&LValue::Ident(name.clone()), true),
            Expr::Index {
                target: inner,
                index,
            } => {
                let mapping = self.lvalue_index_expr(inner)?;
                let key_ty = self.expr(index)?;
                Self::expect(key_ty, mapping.key, "mapping key")?;
                Ok(mapping.value)
            }
            Expr::Access { target, field } => {
                let struct_name = self.lvalue_access_expr(target)?;
                self.resolve_struct_field(&struct_name, field)
            }
            _ => Err(unsupported("non-variable assignment target")),
        }
    }

    /// Resolve an `Expr` that is the target of `Expr::Index` (mapping access).
    fn lvalue_index_expr(&mut self, target: &Expr) -> Result<MappingInfo, CompileError> {
        match target {
            Expr::Ident(name) => match self.lookup_state(name) {
                Some(StateKind::Mapping { key, value }) => Ok(MappingInfo { key, value }),
                Some(_) => Err(unsupported(format!(
                    "`{name}` is not a mapping; indexing requires a mapping"
                ))),
                None => Err(unsupported(format!("unknown identifier `{name}`"))),
            },
            _ => Err(unsupported("mapping index target must be a named variable")),
        }
    }

    /// Resolve an `Expr` that is the target of `Expr::Access` (struct member access).
    fn lvalue_access_expr(&mut self, target: &str) -> Result<String, CompileError> {
        match self.lookup_state(target) {
            Some(StateKind::Struct(name)) => Ok(name),
            Some(_) => Err(unsupported(format!(
                "`{target}` is not a struct; member access requires a struct"
            ))),
            None => Err(unsupported(format!("unknown identifier `{target}`"))),
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
