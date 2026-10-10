use crate::ast::{
    Block, Contract, ContractKind, CustomError, DaoCurrencyDeclaration, DaoDeclaration,
    DaoPegDeclaration, Enum, Event, Expr, Function, FunctionKind, LValue, Modifier,
    ModifierInvocation, Mutability, Param, Statement, Struct, Type, Variable, Visibility,
};
use pest::error::ErrorVariant;
use pest::iterators::Pair;
use pest::Parser;
use pest_derive::Parser;

#[derive(Parser)]
#[grammar = "solidity.pest"]
pub struct SolidParser;

pub use pest::error::Error as PestError;
pub fn parse_contract(input: &str) -> Result<Contract, PestError<Rule>> {
    let source = SolidParser::parse(Rule::source_unit, input)?
        .next()
        .unwrap();
    let mut pragma = None;
    let mut imports = Vec::new();
    let mut definition = None;
    for part in source.into_inner() {
        match part.as_rule() {
            Rule::pragma => pragma = Some(part.as_str().to_owned()),
            Rule::import_declaration => {
                if let Some(path) = part
                    .into_inner()
                    .find(|p| p.as_rule() == Rule::string_literal)
                {
                    imports.push(parse_string(path));
                }
            }
            Rule::contract_definition => definition = Some(part),
            _ => {}
        }
    }
    let mut contract =
        build_contract(definition.expect("source_unit requires a contract definition"))?;
    contract.pragma = pragma;
    contract.imports = imports;
    Ok(contract)
}

fn conversion_error(pair: &Pair<Rule>, message: impl Into<String>) -> PestError<Rule> {
    PestError::new_from_span(
        ErrorVariant::CustomError {
            message: message.into(),
        },
        pair.as_span(),
    )
}

fn build_contract(pair: Pair<Rule>) -> Result<Contract, PestError<Rule>> {
    let mut inner = pair.clone().into_inner();
    let kind = match inner.next().expect("contract kind").as_str() {
        "interface" => ContractKind::Interface,
        "library" => ContractKind::Library,
        _ => ContractKind::Contract,
    };
    let name_ = inner.next().expect("contract name").as_str().to_owned();
    let mut contract = Contract {
        name_,
        kind,
        pragma: None,
        imports: vec![],
        parents: Vec::new(),
        variables: Vec::new(),
        functions: Vec::new(),
        events: Vec::new(),
        structs: Vec::new(),
        enums: Vec::new(),
        modifiers: Vec::new(),
        errors: Vec::new(),
        dao: None,
    };

    for item in inner {
        match item.as_rule() {
            Rule::inheritance => {
                contract.parents.extend(
                    item.into_inner()
                        .filter(|parent| parent.as_rule() == Rule::inheritance_item)
                        .filter_map(|parent| {
                            parent
                                .into_inner()
                                .find(|part| part.as_rule() == Rule::identifier)
                                .map(|name| name.as_str().to_owned())
                        }),
                );
            }
            Rule::contract_item => {
                let definition = item.into_inner().next().expect("contract item");
                match definition.as_rule() {
                    Rule::state_variable => contract.variables.push(parse_variable(definition)?),
                    Rule::function_definition
                    | Rule::constructor_definition
                    | Rule::fallback_definition
                    | Rule::receive_definition => {
                        contract.functions.push(parse_function(definition)?)
                    }
                    Rule::event_definition => contract.events.push(parse_event(definition)?),
                    Rule::error_definition => contract.errors.push(parse_custom_error(definition)?),
                    Rule::struct_definition => contract.structs.push(parse_struct(definition)?),
                    Rule::enum_definition => contract.enums.push(parse_enum(definition)?),
                    Rule::modifier_definition => {
                        contract.modifiers.push(parse_modifier(definition)?)
                    }
                    Rule::dao_definition => contract.dao = Some(parse_dao(definition)?),
                    _ => {}
                }
            }
            _ => {}
        }
    }
    Ok(contract)
}

fn parse_dao(pair: Pair<Rule>) -> Result<DaoDeclaration, PestError<Rule>> {
    let mut makers = Vec::new();
    let mut currency = None;
    let mut peg = None;
    for field in pair.into_inner() {
        match field.as_rule() {
            Rule::dao_makers => {
                makers = field
                    .into_inner()
                    .filter(|part| part.as_rule() == Rule::string_literal)
                    .map(parse_string)
                    .collect();
            }
            Rule::dao_currency => {
                let declaration = field.into_inner().next().expect("DAO currency variant");
                if declaration.as_rule() == Rule::dao_currency_optional {
                    let mut inner = declaration.into_inner();
                    let symbol = parse_string(inner.next().expect("DAO currency symbol"));
                    let amount = inner.next().expect("DAO initial supply");
                    currency = Some(DaoCurrencyDeclaration {
                        symbol,
                        initial_supply: parse_dao_amount(amount)?,
                    });
                }
            }
            Rule::dao_peg => {
                let declaration = field.into_inner().next().expect("DAO peg variant");
                if declaration.as_rule() == Rule::dao_peg_some {
                    let mut inner = declaration.into_inner();
                    let target_dao = parse_string(inner.next().expect("DAO peg target"));
                    let numerator = parse_dao_amount(inner.next().expect("DAO peg numerator"))?;
                    let denominator = parse_dao_amount(inner.next().expect("DAO peg denominator"))?;
                    peg = Some(DaoPegDeclaration {
                        target_dao,
                        numerator,
                        denominator,
                    });
                }
            }
            _ => {}
        }
    }
    Ok(DaoDeclaration {
        makers,
        currency,
        peg,
    })
}

fn parse_dao_amount(pair: Pair<Rule>) -> Result<u128, PestError<Rule>> {
    pair.as_str()
        .replace('_', "")
        .parse::<u128>()
        .map_err(|error| conversion_error(&pair, format!("invalid DAO amount: {error}")))
}

fn parse_type(pair: Pair<Rule>) -> Result<Type, PestError<Rule>> {
    let text = pair.as_str().to_owned();
    if pair.as_rule() == Rule::elementary_type {
        return Ok(elementary_type(pair.as_str().trim()));
    }
    let mut inner = pair.clone().into_inner();
    let Some(first) = inner.next() else {
        return Err(conversion_error(&pair, format!("invalid type `{text}`")));
    };
    let mut ty = match first.as_rule() {
        Rule::mapping_type => {
            let mut mapping = first.into_inner();
            let key = parse_type(mapping.next().expect("mapping key"))?;
            let value = parse_type(mapping.next().expect("mapping value"))?;
            Type::Mapping {
                key: Box::new(key),
                value: Box::new(value),
            }
        }
        Rule::elementary_type => elementary_type(first.as_str()),
        Rule::identifier => Type::Named(first.as_str().to_owned()),
        _ => {
            return Err(conversion_error(
                &pair,
                format!("unsupported type `{text}`"),
            ))
        }
    };

    for suffix in inner {
        if suffix.as_rule() == Rule::array_suffix {
            ty = Type::Array(Box::new(ty));
        }
    }
    Ok(ty)
}

fn elementary_type(name: &str) -> Type {
    let normalized = name.trim_end_matches(" payable");
    match normalized {
        "address" => Type::Address,
        "uint" | "uint256" => Type::U256,
        "uint64" => Type::U64,
        "int" | "int256" => Type::Int(256),
        "int64" => Type::Int(64),
        "bool" => Type::Bool,
        "string" => Type::String,
        "bytes" | "byte" => Type::Bytes,
        "bytes32" => Type::Bytes32,
        _ if normalized.starts_with("uint") => normalized[4..]
            .parse()
            .map(Type::Uint)
            .unwrap_or(Type::U256),
        _ if normalized.starts_with("int") => normalized[3..]
            .parse()
            .map(Type::Int)
            .unwrap_or(Type::Int(256)),
        _ if normalized.starts_with("bytes") => normalized[5..]
            .parse()
            .map(Type::FixedBytes)
            .unwrap_or(Type::Bytes),
        _ => Type::Named(normalized.to_owned()),
    }
}

fn parse_param(pair: Pair<Rule>) -> Result<Param, PestError<Rule>> {
    let ty = parse_type(pair.clone().into_inner().next().expect("parameter type"))?;
    let text = pair.as_str().to_owned();
    let inner = pair.into_inner();
    let name = inner
        .filter(|part| part.as_rule() == Rule::identifier)
        .last()
        .map_or_else(String::new, |part| part.as_str().to_owned());
    Ok(Param {
        name,
        ty,
        indexed: text.split_whitespace().any(|word| word == "indexed"),
    })
}

fn parse_params(pair: Pair<Rule>) -> Result<Vec<Param>, PestError<Rule>> {
    pair.into_inner()
        .filter(|part| part.as_rule() == Rule::parameter)
        .map(parse_param)
        .collect()
}

fn parse_variable(pair: Pair<Rule>) -> Result<Variable, PestError<Rule>> {
    let mut ty = None;
    let mut visibility = Visibility::Internal;
    let mut constant = false;
    let mut immutable = false;
    let mut name = None;
    let mut initializer = None;
    for part in pair.clone().into_inner() {
        match part.as_rule() {
            Rule::type_name => ty = Some(parse_type(part)?),
            Rule::visibility => visibility = parse_visibility(part.as_str()),
            Rule::state_attribute => match part.as_str() {
                "constant" => constant = true,
                "immutable" => immutable = true,
                _ => {}
            },
            Rule::identifier => name = Some(part.as_str().to_owned()),
            Rule::expression => initializer = Some(parse_expression(part)?),
            _ => {}
        }
    }
    Ok(Variable {
        name: name.unwrap_or_default(),
        ty: ty.ok_or_else(|| conversion_error(&pair, "missing variable type"))?,
        mutable: !constant && !immutable,
        visibility,
        constant,
        immutable,
        initializer,
    })
}

fn parse_function(pair: Pair<Rule>) -> Result<Function, PestError<Rule>> {
    let rule = pair.as_rule();
    let kind = match rule {
        Rule::constructor_definition => FunctionKind::Constructor,
        Rule::fallback_definition => FunctionKind::Fallback,
        Rule::receive_definition => FunctionKind::Receive,
        _ => FunctionKind::Function,
    };
    let mut name = match kind {
        FunctionKind::Constructor => "constructor".to_owned(),
        FunctionKind::Fallback => "fallback".to_owned(),
        FunctionKind::Receive => "receive".to_owned(),
        FunctionKind::Function => String::new(),
    };
    let mut visibility = match kind {
        FunctionKind::Fallback | FunctionKind::Receive => Visibility::External,
        _ => Visibility::Internal,
    };
    let mut mutability = None;
    let mut modifiers = Vec::new();
    let mut virtual_ = false;
    let mut overrides = Vec::new();
    let mut inputs = Vec::new();
    let mut outputs = Vec::new();
    let mut body = Block { statements: vec![] };

    for part in pair.clone().into_inner() {
        match part.as_rule() {
            Rule::identifier if name.is_empty() => name = part.as_str().to_owned(),
            Rule::parameter_list => inputs = parse_params(part)?,
            Rule::function_attribute => {
                let attribute = part.as_str().to_owned();
                match part.clone().into_inner().next() {
                    Some(inner) if inner.as_rule() == Rule::visibility => {
                        visibility = parse_visibility(inner.as_str())
                    }
                    Some(inner) if inner.as_rule() == Rule::mutability => {
                        mutability = Some(parse_mutability(inner.as_str()))
                    }
                    Some(inner) if inner.as_rule() == Rule::override_specifier => {
                        overrides = inner
                            .into_inner()
                            .flat_map(Pair::into_inner)
                            .filter(|name| name.as_rule() == Rule::identifier)
                            .map(|name| name.as_str().to_owned())
                            .collect()
                    }
                    Some(inner) if inner.as_rule() == Rule::modifier_invocation => {
                        let mut invocation = inner.into_inner();
                        let name = invocation
                            .find(|name| name.as_rule() == Rule::identifier)
                            .map_or_else(
                                || attribute.split('(').next().unwrap_or("").to_owned(),
                                |name| name.as_str().to_owned(),
                            );
                        let args = invocation
                            .find(|part| part.as_rule() == Rule::argument_list)
                            .map(parse_arguments)
                            .transpose()?
                            .unwrap_or_default();
                        modifiers.push(ModifierInvocation { name, args });
                    }
                    _ if attribute == "virtual" => virtual_ = true,
                    _ => {}
                }
            }
            Rule::returns_clause => {
                if let Some(params) = part
                    .into_inner()
                    .find(|p| p.as_rule() == Rule::parameter_list)
                {
                    outputs = parse_params(params)?;
                }
            }
            Rule::block => body = parse_block(part)?,
            _ => {}
        }
    }

    Ok(Function {
        name,
        kind,
        visibility,
        mutability,
        modifiers,
        virtual_,
        overrides,
        inputs,
        outputs,
        body,
    })
}

fn parse_event(pair: Pair<Rule>) -> Result<Event, PestError<Rule>> {
    let mut inner = pair.clone().into_inner();
    let name = inner.next().expect("event name").as_str().to_owned();
    let params = inner
        .find(|part| part.as_rule() == Rule::event_parameter_list)
        .map(|list| {
            list.into_inner()
                .filter(|part| part.as_rule() == Rule::event_parameter)
                .map(parse_param)
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();
    let indexed = params
        .iter()
        .filter(|param| param.indexed)
        .map(|param| param.name.clone())
        .collect();
    Ok(Event {
        name,
        params,
        indexed,
        anonymous: pair.as_str().contains("anonymous"),
    })
}

fn parse_custom_error(pair: Pair<Rule>) -> Result<CustomError, PestError<Rule>> {
    let mut inner = pair.into_inner();
    let name = inner.next().expect("error name").as_str().to_owned();
    let inputs = inner
        .find(|part| part.as_rule() == Rule::parameter_list)
        .map(parse_params)
        .transpose()?
        .unwrap_or_default();
    Ok(CustomError { name, inputs })
}

fn parse_struct(pair: Pair<Rule>) -> Result<Struct, PestError<Rule>> {
    let mut inner = pair.into_inner();
    let name = inner.next().expect("struct name").as_str().to_owned();
    let fields = inner
        .filter(|part| part.as_rule() == Rule::struct_field)
        .map(|field| {
            let mut field_parts = field.into_inner();
            Ok(Param {
                ty: parse_type(field_parts.next().expect("field type"))?,
                name: field_parts.next().expect("field name").as_str().to_owned(),
                indexed: false,
            })
        })
        .collect::<Result<Vec<_>, PestError<Rule>>>()?;
    Ok(Struct { name, fields })
}

fn parse_enum(pair: Pair<Rule>) -> Result<Enum, PestError<Rule>> {
    let mut inner = pair.into_inner();
    let name = inner.next().expect("enum name").as_str().to_owned();
    let variants = inner
        .find(|part| part.as_rule() == Rule::identifier_list)
        .map(|list| list.into_inner().map(|v| v.as_str().to_owned()).collect())
        .unwrap_or_default();
    Ok(Enum { name, variants })
}

fn parse_modifier(pair: Pair<Rule>) -> Result<Modifier, PestError<Rule>> {
    let mut inner = pair.into_inner();
    let name = inner.next().expect("modifier name").as_str().to_owned();
    let inputs = inner
        .find(|part| part.as_rule() == Rule::parameter_list)
        .map(parse_params)
        .transpose()?
        .unwrap_or_default();
    let body = inner
        .find(|part| part.as_rule() == Rule::block)
        .map(parse_block)
        .transpose()?
        .unwrap_or(Block { statements: vec![] });
    Ok(Modifier { name, inputs, body })
}

fn parse_block(pair: Pair<Rule>) -> Result<Block, PestError<Rule>> {
    let statements = pair
        .into_inner()
        .filter(|part| part.as_rule() == Rule::statement)
        .map(parse_statement)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Block { statements })
}

fn parse_statement(pair: Pair<Rule>) -> Result<Statement, PestError<Rule>> {
    let pair = if pair.as_rule() == Rule::statement {
        pair.into_inner().next().expect("statement")
    } else {
        pair
    };
    match pair.as_rule() {
        Rule::block => parse_block(pair).map(Statement::Block),
        Rule::if_statement => {
            let mut inner = pair.into_inner();
            let condition = parse_expression(inner.next().expect("if condition"))?;
            let true_block = statement_as_block(inner.next().expect("if body"))?;
            let false_block = inner.next().map(statement_as_block).transpose()?;
            Ok(Statement::If {
                condition,
                true_block,
                false_block,
            })
        }
        Rule::for_statement => parse_for(pair),
        Rule::while_statement => {
            let mut inner = pair.into_inner();
            let cond = parse_expression(inner.next().expect("while condition"))?;
            let block = statement_as_block(inner.next().expect("while body"))?;
            Ok(Statement::While { cond, block })
        }
        Rule::do_while_statement => {
            let mut inner = pair.into_inner();
            let block = statement_as_block(inner.next().expect("do body"))?;
            let cond = parse_expression(inner.next().expect("do-while condition"))?;
            Ok(Statement::DoWhile { block, cond })
        }
        Rule::return_statement => {
            let value = pair
                .into_inner()
                .find(|part| part.as_rule() == Rule::expression)
                .map(parse_expression)
                .transpose()?;
            Ok(Statement::Return(value))
        }
        Rule::emit_statement => {
            let call = pair.into_inner().next().expect("emitted call");
            let (event, args) = parse_call(call)?;
            Ok(Statement::Emitevent {
                event,
                args: args.into_iter().map(|expr| (String::new(), expr)).collect(),
            })
        }
        Rule::assert_statement | Rule::require_statement => {
            let is_assert = pair.as_rule() == Rule::assert_statement;
            let mut inner = pair.into_inner();
            let condition = parse_expression(inner.next().expect("condition"))?;
            let message = inner
                .find(|part| part.as_rule() == Rule::string_literal)
                .map(parse_string);
            if is_assert {
                Ok(Statement::Assert {
                    condition,
                    message: message.unwrap_or_default(),
                })
            } else {
                Ok(Statement::Require { condition, message })
            }
        }
        Rule::revert_statement => {
            let detail = pair.into_inner().next();
            if let Some(detail) = detail {
                if detail.as_rule() == Rule::function_call {
                    let (error, args) = parse_call(detail)?;
                    Ok(Statement::Revert {
                        error: Some(error),
                        args,
                    })
                } else if detail.as_rule() == Rule::string_literal {
                    Ok(Statement::Revert {
                        error: None,
                        args: vec![Expr::LitString(parse_string(detail))],
                    })
                } else {
                    Ok(Statement::Revert {
                        error: None,
                        args: detail
                            .into_inner()
                            .find(|part| part.as_rule() == Rule::string_literal)
                            .map(parse_string)
                            .map(|s| vec![Expr::LitString(s)])
                            .unwrap_or_default(),
                    })
                }
            } else {
                Ok(Statement::Revert {
                    error: None,
                    args: vec![],
                })
            }
        }
        Rule::break_statement => Ok(Statement::Break),
        Rule::continue_statement => Ok(Statement::Continue),
        Rule::modifier_placeholder => Ok(Statement::Placeholder),
        Rule::variable_declaration => {
            let declaration = pair.into_inner().next().expect("variable declaration");
            parse_local_variable(declaration)
        }
        Rule::assignment_statement => parse_assignment_statement(pair),
        Rule::expression_statement => {
            let expr = parse_expression(pair.into_inner().next().expect("expression"))?;
            match expr {
                Expr::Assign { target, op, value } if op == "=" => {
                    Ok(Statement::Expression(Expr::Assign { target, op, value }))
                }
                other => Ok(Statement::Expression(other)),
            }
        }
        _ => Err(conversion_error(&pair, "unsupported statement")),
    }
}

fn statement_as_block(pair: Pair<Rule>) -> Result<Block, PestError<Rule>> {
    if pair.as_rule() == Rule::block {
        parse_block(pair)
    } else {
        Ok(Block {
            statements: vec![parse_statement(pair)?],
        })
    }
}

fn parse_for(pair: Pair<Rule>) -> Result<Statement, PestError<Rule>> {
    let mut inner = pair.into_inner();
    let mut init = None;
    let mut cond = None;
    let mut update = None;
    let mut body = None;
    for part in inner.by_ref() {
        match part.as_rule() {
            Rule::for_init => {
                let item = part.into_inner().next().expect("for initializer");
                init = Some(Box::new(
                    if item.as_rule() == Rule::variable_declaration_no_semicolon {
                        parse_local_variable(item)?
                    } else {
                        Statement::Expression(parse_expression(item)?)
                    },
                ));
            }
            Rule::for_condition => {
                cond = part.into_inner().next().map(parse_expression).transpose()?;
            }
            Rule::for_update => {
                update = part.into_inner().next().map(parse_expression).transpose()?;
            }
            Rule::statement => body = Some(statement_as_block(part)?),
            _ => {}
        }
    }
    Ok(Statement::For {
        init,
        cond,
        update,
        block: body.unwrap_or(Block { statements: vec![] }),
    })
}

fn parse_local_variable(pair: Pair<Rule>) -> Result<Statement, PestError<Rule>> {
    let mut inner = pair.clone().into_inner();
    let ty = parse_type(inner.next().expect("local variable type"))?;
    let mut name = String::new();
    let mut init = None;
    for part in inner {
        match part.as_rule() {
            Rule::identifier => name = part.as_str().to_owned(),
            Rule::expression => init = Some(parse_expression(part)?),
            _ => {}
        }
    }
    Ok(Statement::Let { name, ty, init })
}

fn parse_assignment_statement(pair: Pair<Rule>) -> Result<Statement, PestError<Rule>> {
    let mut inner = pair.clone().into_inner();
    let target = parse_lvalue(inner.next().expect("assignment target"))?;
    let op = inner
        .next()
        .expect("assignment operator")
        .as_str()
        .to_owned();
    let value = parse_expression(inner.next().expect("assignment value"))?;
    if op == "=" {
        Ok(Statement::Assign { target, value })
    } else {
        Ok(Statement::Expression(Expr::Assign {
            target: Box::new(lvalue_to_expr(target)),
            op,
            value: Box::new(value),
        }))
    }
}

fn parse_lvalue(pair: Pair<Rule>) -> Result<LValue, PestError<Rule>> {
    let mut inner = pair.into_inner();
    let mut target = LValue::Ident(inner.next().expect("lvalue identifier").as_str().to_owned());
    for part in inner {
        target = match part.as_rule() {
            Rule::identifier => LValue::Member {
                base: Box::new(target),
                field: part.as_str().to_owned(),
            },
            Rule::expression => LValue::Index {
                base: Box::new(target),
                index: parse_expression(part)?,
            },
            _ => target,
        };
    }
    Ok(target)
}

fn lvalue_to_expr(target: LValue) -> Expr {
    match target {
        LValue::Ident(name) => Expr::Ident(name),
        LValue::Index { base, index } => Expr::Index {
            target: Box::new(lvalue_to_expr(*base)),
            index: Box::new(index),
        },
        LValue::Member { base, field } => Expr::Access {
            target: lvalue_to_string(*base),
            field,
        },
    }
}

fn lvalue_to_string(target: LValue) -> String {
    match target {
        LValue::Ident(name) => name,
        LValue::Index { base, index } => {
            format!("{}[{:?}]", lvalue_to_string(*base), index)
        }
        LValue::Member { base, field } => format!("{}.{}", lvalue_to_string(*base), field),
    }
}

fn parse_expression(pair: Pair<Rule>) -> Result<Expr, PestError<Rule>> {
    match pair.as_rule() {
        Rule::expression => parse_expression(pair.into_inner().next().expect("expression body")),
        Rule::assignment_expression => {
            let mut inner = pair.into_inner();
            let left = parse_expression(inner.next().expect("assignment left"))?;
            if let Some(operator) = inner.next() {
                let right = parse_expression(inner.next().expect("assignment right"))?;
                Ok(Expr::Assign {
                    target: Box::new(left),
                    op: operator.as_str().to_owned(),
                    value: Box::new(right),
                })
            } else {
                Ok(left)
            }
        }
        Rule::ternary => {
            let mut inner = pair.into_inner();
            let condition = parse_expression(inner.next().expect("ternary condition"))?;
            if let Some(yes) = inner.next() {
                let yes = parse_expression(yes)?;
                let no = parse_expression(inner.next().expect("ternary false expression"))?;
                Ok(Expr::Ternary {
                    condition: Box::new(condition),
                    true_expr: Box::new(yes),
                    false_expr: Box::new(no),
                })
            } else {
                Ok(condition)
            }
        }
        Rule::logical_or
        | Rule::logical_and
        | Rule::bitwise_or
        | Rule::bitwise_xor
        | Rule::bitwise_and
        | Rule::equality
        | Rule::comparison
        | Rule::shift
        | Rule::term
        | Rule::factor => parse_binary(pair),
        Rule::power => {
            let mut inner = pair.into_inner();
            let left = parse_expression(inner.next().expect("power left"))?;
            if let Some(_operator) = inner.next() {
                let right = parse_expression(inner.next().expect("power right"))?;
                Ok(Expr::Pow(Box::new(left), Box::new(right)))
            } else {
                Ok(left)
            }
        }
        Rule::unary => {
            let mut inner = pair.into_inner().peekable();
            let mut prefixes = Vec::new();
            while inner
                .peek()
                .is_some_and(|part| part.as_rule() == Rule::prefix_op)
            {
                prefixes.push(inner.next().expect("prefix").as_str().to_owned());
            }
            let mut value = parse_expression(inner.next().expect("unary operand"))?;
            if let Some(postfix) = inner.next() {
                let increment = postfix.as_str() == "++";
                value = Expr::Update {
                    target: Box::new(value),
                    increment,
                    prefix: false,
                };
            }
            for prefix in prefixes.into_iter().rev() {
                value = match prefix.as_str() {
                    "!" => Expr::Not(Box::new(value)),
                    "~" => Expr::BitXor(Box::new(value), Box::new(Expr::LitInt(u64::MAX))),
                    "-" => Expr::UMinus(Box::new(value)),
                    "++" | "--" => Expr::Update {
                        target: Box::new(value),
                        increment: prefix == "++",
                        prefix: true,
                    },
                    _ => value,
                };
            }
            Ok(value)
        }
        Rule::postfix => {
            let mut inner = pair.into_inner();
            let mut value = parse_expression(inner.next().expect("postfix expression"))?;
            if let Some(operator) = inner.next() {
                value = Expr::Update {
                    target: Box::new(value),
                    increment: operator.as_str() == "++",
                    prefix: false,
                };
            }
            Ok(value)
        }
        Rule::primary => {
            let primary = pair.into_inner().next().expect("primary");
            match primary.as_rule() {
                Rule::literal => parse_literal(primary),
                Rule::function_call => {
                    let (func, args) = parse_call(primary)?;
                    Ok(Expr::Call { func, args })
                }
                Rule::member_access => parse_member_access(primary),
                Rule::index_access => parse_index_access(primary),
                Rule::identifier => Ok(Expr::Ident(primary.as_str().to_owned())),
                Rule::expression => parse_expression(primary),
                _ => Err(conversion_error(&primary, "unsupported expression")),
            }
        }
        _ => Err(conversion_error(&pair, "unsupported expression")),
    }
}

fn parse_binary(pair: Pair<Rule>) -> Result<Expr, PestError<Rule>> {
    let rule = pair.as_rule();
    let mut inner = pair.into_inner();
    let mut value = parse_expression(inner.next().expect("left operand"))?;
    while let Some(operator) = inner.next() {
        let op = operator.as_str();
        let right = parse_expression(inner.next().expect("right operand"))?;
        value = match (rule, op) {
            (Rule::logical_or, _) => Expr::Or(Box::new(value), Box::new(right)),
            (Rule::logical_and, _) => Expr::And(Box::new(value), Box::new(right)),
            (Rule::bitwise_or, _) => Expr::BitOr(Box::new(value), Box::new(right)),
            (Rule::bitwise_xor, _) => Expr::BitXor(Box::new(value), Box::new(right)),
            (Rule::bitwise_and, _) => Expr::BitAnd(Box::new(value), Box::new(right)),
            (Rule::equality, "==") => Expr::Eq(Box::new(value), Box::new(right)),
            (Rule::equality, _) => Expr::Neq(Box::new(value), Box::new(right)),
            (Rule::comparison, "<") => Expr::Lt(Box::new(value), Box::new(right)),
            (Rule::comparison, "<=") => Expr::Lte(Box::new(value), Box::new(right)),
            (Rule::comparison, ">") => Expr::Gt(Box::new(value), Box::new(right)),
            (Rule::comparison, _) => Expr::Gte(Box::new(value), Box::new(right)),
            (Rule::shift, "<<") => Expr::Shl(Box::new(value), Box::new(right)),
            (Rule::shift, _) => Expr::Shr(Box::new(value), Box::new(right)),
            (Rule::term, "+") => Expr::Add(Box::new(value), Box::new(right)),
            (Rule::term, _) => Expr::Sub(Box::new(value), Box::new(right)),
            (Rule::factor, "*") => Expr::Mul(Box::new(value), Box::new(right)),
            (Rule::factor, "/") => Expr::Div(Box::new(value), Box::new(right)),
            (Rule::factor, _) => Expr::Mod(Box::new(value), Box::new(right)),
            _ => value,
        };
    }
    Ok(value)
}

fn parse_literal(pair: Pair<Rule>) -> Result<Expr, PestError<Rule>> {
    let literal = pair.into_inner().next().expect("literal");
    match literal.as_rule() {
        Rule::number_literal => {
            let value = literal.as_str().replace('_', "");
            if value.contains('.') {
                Ok(Expr::LitDecimal(value))
            } else {
                Ok(value
                    .parse::<u64>()
                    .map_or_else(|_| Expr::LitNumber(value.clone()), Expr::LitInt))
            }
        }
        Rule::boolean_literal => Ok(Expr::LitBool(literal.as_str() == "true")),
        Rule::hex_number => Ok(Expr::LitNumber(literal.as_str().to_owned())),
        Rule::string_literal => Ok(Expr::LitString(parse_string(literal))),
        Rule::address_literal => {
            let bytes = hex::decode(&literal.as_str()[2..])
                .map_err(|error| conversion_error(&literal, error.to_string()))?;
            let address: [u8; 20] = bytes
                .try_into()
                .map_err(|_| conversion_error(&literal, "address must be 20 bytes"))?;
            Ok(Expr::Address(address))
        }
        _ => Err(conversion_error(&literal, "unsupported literal")),
    }
}

fn parse_string(pair: Pair<Rule>) -> String {
    let raw = pair.as_str();
    serde_json::from_str(raw).unwrap_or_else(|_| raw.trim_matches('"').to_owned())
}

fn parse_call(pair: Pair<Rule>) -> Result<(String, Vec<Expr>), PestError<Rule>> {
    let mut inner = pair.into_inner();
    let callee = inner.next().expect("function name");
    let name = match callee.as_rule() {
        Rule::identifier => callee.as_str().to_owned(),
        Rule::member_access => member_access_name(callee),
        _ => callee.as_str().to_owned(),
    };
    let args = inner
        .find(|part| part.as_rule() == Rule::argument_list)
        .map(parse_arguments)
        .transpose()?
        .unwrap_or_default();
    Ok((name, args))
}

fn parse_arguments(pair: Pair<Rule>) -> Result<Vec<Expr>, PestError<Rule>> {
    pair.into_inner().map(parse_expression).collect()
}

fn parse_member_access(pair: Pair<Rule>) -> Result<Expr, PestError<Rule>> {
    let parts = pair
        .into_inner()
        .map(|part| part.as_str().to_owned())
        .collect::<Vec<_>>();
    let (field, target) = parts.split_last().expect("member expression");
    Ok(Expr::Access {
        target: target.join("."),
        field: field.clone(),
    })
}

fn member_access_name(pair: Pair<Rule>) -> String {
    pair.into_inner()
        .map(|part| part.as_str().to_owned())
        .collect::<Vec<_>>()
        .join(".")
}

fn parse_index_access(pair: Pair<Rule>) -> Result<Expr, PestError<Rule>> {
    let mut inner = pair.into_inner();
    let base = inner.next().expect("index target");
    let mut target = match base.as_rule() {
        Rule::identifier => Expr::Ident(base.as_str().to_owned()),
        Rule::member_access => parse_member_access(base)?,
        _ => return Err(conversion_error(&base, "invalid index target")),
    };
    for index in inner {
        target = Expr::Index {
            target: Box::new(target),
            index: Box::new(parse_expression(index)?),
        };
    }
    Ok(target)
}

fn parse_visibility(value: &str) -> Visibility {
    match value {
        "public" => Visibility::Public,
        "private" => Visibility::Private,
        "external" => Visibility::External,
        _ => Visibility::Internal,
    }
}

fn parse_mutability(value: &str) -> Mutability {
    match value {
        "pure" => Mutability::Pure,
        "payable" => Mutability::Payable,
        _ => Mutability::View,
    }
}
