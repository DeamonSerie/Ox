use crate::ast::{Expr, LValue, Statement, Type, Visibility};

/// Generate Rust source code from a contract AST
pub fn rust_source(contract: &crate::ast::Contract) -> String {
    let name = &contract.name_;
    let parents = &contract.parents;
    let vars = &contract.variables;
    let funcs = &contract.functions;
    let events = &contract.events;

    let mut output = String::new();

    // Add license/header
    output.push_str("// Auto-generated from Solidity-like DSL\n");
    output.push_str(&format!("\ncontract {} {{\n", name));

    // Parents
    if !parents.is_empty() {
        output.push_str(&format!("    // Inherits from: {}\n", parents.join(", ")));
    }

    // State variables
    output.push_str("\n    // State Variables\n");
    for var in vars {
        let mutty = if var.mutable { "mut " } else { "" };
        let ty_str = type_to_rust(&var.ty);
        output.push_str(&format!("    {} {};\n", mutty, ty_str));
    }

    // Functions
    output.push_str("\n    // Functions\n");
    for func in funcs {
        let vis = visibility_to_rust(&func.visibility);
        let name = &func.name;
        let inputs: Vec<String> = func
            .inputs
            .iter()
            .map(|p| format!("{} {}", type_to_rust(&p.ty), p.name))
            .collect();
        let outputs: Vec<String> = func.outputs.iter().map(|p| type_to_rust(&p.ty)).collect();

        output.push_str(&format!("    {} fn {}(", vis, name));
        output.push_str(&inputs.join(", "));
        output.push_str(") -> (");
        output.push_str(&outputs.join(", "));
        output.push_str(") {\n");

        // Generate body statements
        for stmt in &func.body.statements {
            output.push_str(&format_statement(stmt, 4));
        }

        output.push_str("    }\n");
    }

    // Events
    output.push_str("\n    // Events\n");
    for event in events {
        let params: Vec<String> = event
            .params
            .iter()
            .map(|p| format!("{} {}", type_to_rust(&p.ty), p.name))
            .collect();
        output.push_str(&format!(
            "    event {}({});\n",
            event.name,
            params.join(", ")
        ));
    }

    output.push_str("}\n");
    output
}

/// Convert Type to Rust type string
fn type_to_rust(ty: &Type) -> String {
    match ty {
        Type::Address => "Address".to_string(),
        Type::U64 => "u64".to_string(),
        Type::U256 => "u64".to_string(), // Simplified: use u64 for u256
        Type::Uint(width) => format!("u{width}"),
        Type::Int(width) => format!("i{width}"),
        Type::Bytes => "Vec<u8>".to_string(),
        Type::Bytes32 => "[u8; 32]".to_string(),
        Type::FixedBytes(width) => format!("[u8; {width}]"),
        Type::Bool => "bool".to_string(),
        Type::String => "String".to_string(),
        Type::Named(name) => name.clone(),
        Type::Array(inner) => format!("Vec<{}>", type_to_rust(inner)),
        Type::Mapping { key, value } => {
            format!(
                "std::collections::HashMap<{}, {}>",
                type_to_rust(key),
                type_to_rust(value)
            )
        }
    }
}

/// Convert Visibility to Rust visibility
fn visibility_to_rust(vis: &Visibility) -> String {
    match vis {
        Visibility::Public => "pub",
        Visibility::Internal => "",
        Visibility::Private => "private",
        Visibility::External => "pub",
    }
    .to_string()
}

/// Format a statement with indentation
fn format_statement(stmt: &Statement, indent: usize) -> String {
    let spaces = " ".repeat(indent);
    match stmt {
        Statement::Let { name, ty, init } => {
            let init_str = init
                .as_ref()
                .map_or(String::new(), |e| format!(" = {}", expr_to_rust(e)));
            format!(
                "{}let {}: {} = {};\n",
                spaces,
                name,
                type_to_rust(ty),
                init_str
            )
        }
        Statement::Assign { target, value } => {
            let target = lvalue_to_rust(target);
            format!("{} {} = {};\n", spaces, target, expr_to_rust(value))
        }
        Statement::If {
            condition,
            true_block,
            false_block,
        } => {
            let mut result = format!("{}if {} {{\n", spaces, expr_to_rust(condition));
            for stmt in &true_block.statements {
                result.push_str(&format_statement(stmt, indent + 4));
            }
            result.push_str(&format!("{}}}\n", spaces));
            if let Some(fb) = false_block {
                result.push_str(&format!("{}else {{\n", spaces));
                for stmt in &fb.statements {
                    result.push_str(&format_statement(stmt, indent + 4));
                }
                result.push_str(&format!("{}}}\n", spaces));
            }
            result
        }
        Statement::For {
            init,
            cond,
            update,
            block,
        } => {
            let init_str = init.as_ref().map_or(String::new(), |statement| {
                format_statement(statement, 0)
                    .trim()
                    .trim_end_matches(';')
                    .to_string()
            });
            let cond_str = cond.as_ref().map_or(String::new(), expr_to_rust);
            let update_str = update
                .as_ref()
                .map_or(String::new(), |e| format!("{}", expr_to_rust(e)));
            let mut result = format!(
                "{}for ({}; {}; {}) {{\n",
                spaces, init_str, cond_str, update_str
            );
            for stmt in &block.statements {
                result.push_str(&format_statement(stmt, indent + 4));
            }
            result.push_str(&format!("{}}}\n", spaces));
            result
        }
        Statement::While { cond, block } => {
            let mut result = format!("{}while {} {{\n", spaces, expr_to_rust(cond));
            for stmt in &block.statements {
                result.push_str(&format_statement(stmt, indent + 4));
            }
            result.push_str(&format!("{}}}\n", spaces));
            result
        }
        Statement::DoWhile { block, cond } => {
            let mut result = format!("{}loop {{\n", spaces);
            for stmt in &block.statements {
                result.push_str(&format_statement(stmt, indent + 4));
            }
            result.push_str(&format!(
                "{}    if !({}) {{ break; }}\n",
                spaces,
                expr_to_rust(cond)
            ));
            result.push_str(&format!("{}}}\n", spaces));
            result
        }
        Statement::Return(Some(val)) => format!("{}return {};\n", spaces, expr_to_rust(val)),
        Statement::Return(None) => format!("{}return;\n", spaces),
        Statement::Emitevent { event, args } => {
            let args_str: Vec<String> = args.iter().map(|(_, expr)| expr_to_rust(expr)).collect();
            format!("{}emit {}({});\n", spaces, event, args_str.join(", "))
        }
        Statement::Assert { condition, message } => {
            format!(
                "{}assert!({}, {:?});\n",
                spaces,
                expr_to_rust(condition),
                message
            )
        }
        Statement::Break => format!("{}break;\n", spaces),
        Statement::Continue => format!("{}continue;\n", spaces),
        Statement::Require { condition, message } => match message {
            Some(message) => format!(
                "{}assert!({}, {:?});\n",
                spaces,
                expr_to_rust(condition),
                message
            ),
            None => format!("{}assert!({});\n", spaces, expr_to_rust(condition)),
        },
        Statement::Revert { error, args } => {
            let error_name = error.as_deref().unwrap_or("revert");
            let args = args.iter().map(expr_to_rust).collect::<Vec<_>>().join(", ");
            format!("{}return Err({}({}));\n", spaces, error_name, args)
        }
        Statement::Placeholder => format!("{}/* modifier body */\n", spaces),
        Statement::Expression(expr) => format!("{}{};\n", spaces, expr_to_rust(expr)),
        Statement::Block(block) => {
            let mut result = format!("{}{{\n", spaces);
            for stmt in &block.statements {
                result.push_str(&format_statement(stmt, indent + 4));
            }
            result.push_str(&format!("{}}}\n", spaces));
            result
        }
    }
}

/// Convert Expr to Rust expression string
fn expr_to_rust(expr: &Expr) -> String {
    match expr {
        Expr::LitInt(n) => n.to_string(),
        Expr::LitNumber(n) | Expr::LitDecimal(n) => n.clone(),
        Expr::LitBool(b) => b.to_string(),
        Expr::LitString(s) => format!("\"{}\"", s),
        Expr::Address(_addr) => {
            // Simplified: just return a placeholder
            "address".to_string()
        }
        Expr::Ident(name) => name.clone(),
        Expr::Add(left, right) => format!("({} + {})", expr_to_rust(left), expr_to_rust(right)),
        Expr::Sub(left, right) => format!("({} - {})", expr_to_rust(left), expr_to_rust(right)),
        Expr::Mul(left, right) => format!("({} * {})", expr_to_rust(left), expr_to_rust(right)),
        Expr::Div(left, right) => format!("({} / {})", expr_to_rust(left), expr_to_rust(right)),
        Expr::Mod(left, right) => format!("({} % {})", expr_to_rust(left), expr_to_rust(right)),
        Expr::Eq(left, right) => format!("({} == {})", expr_to_rust(left), expr_to_rust(right)),
        Expr::Neq(left, right) => format!("({} != {})", expr_to_rust(left), expr_to_rust(right)),
        Expr::Gt(left, right) => format!("({} > {})", expr_to_rust(left), expr_to_rust(right)),
        Expr::Lt(left, right) => format!("({} < {})", expr_to_rust(left), expr_to_rust(right)),
        Expr::Gte(left, right) => format!("({} >= {})", expr_to_rust(left), expr_to_rust(right)),
        Expr::Lte(left, right) => format!("({} <= {})", expr_to_rust(left), expr_to_rust(right)),
        Expr::Not(inner) => format!("!{}", expr_to_rust(inner)),
        Expr::And(left, right) => format!("({} && {})", expr_to_rust(left), expr_to_rust(right)),
        Expr::Or(left, right) => format!("({} || {})", expr_to_rust(left), expr_to_rust(right)),
        Expr::UMinus(inner) => format!("-{}", expr_to_rust(inner)),
        Expr::Call { func, args } => {
            let args_str: Vec<String> = args.iter().map(expr_to_rust).collect();
            format!("{}({})", func, args_str.join(", "))
        }
        Expr::Access { target, field } => format!("{}.{}", target, field),
        Expr::Index { target, index } => {
            format!("{}[{}]", expr_to_rust(target), expr_to_rust(index))
        }
        Expr::Ternary {
            condition,
            true_expr,
            false_expr,
        } => format!(
            "(if {} {{ {} }} else {{ {} }})",
            expr_to_rust(condition),
            expr_to_rust(true_expr),
            expr_to_rust(false_expr)
        ),
        Expr::Pow(left, right) => {
            format!("{}.pow({} as u32)", expr_to_rust(left), expr_to_rust(right))
        }
        Expr::BitAnd(left, right) => format!("({} & {})", expr_to_rust(left), expr_to_rust(right)),
        Expr::BitOr(left, right) => format!("({} | {})", expr_to_rust(left), expr_to_rust(right)),
        Expr::BitXor(left, right) => format!("({} ^ {})", expr_to_rust(left), expr_to_rust(right)),
        Expr::Shl(left, right) => format!("({} << {})", expr_to_rust(left), expr_to_rust(right)),
        Expr::Shr(left, right) => format!("({} >> {})", expr_to_rust(left), expr_to_rust(right)),
        Expr::Assign { target, op, value } => {
            format!("({} {} {})", expr_to_rust(target), op, expr_to_rust(value))
        }
        Expr::Update {
            target,
            increment,
            prefix,
        } => {
            let operator = if *increment { "++" } else { "--" };
            if *prefix {
                format!("{}{}", operator, expr_to_rust(target))
            } else {
                format!("{}{}", expr_to_rust(target), operator)
            }
        }
    }
}

fn lvalue_to_rust(target: &LValue) -> String {
    match target {
        LValue::Ident(name) => name.clone(),
        LValue::Index { base, index } => {
            format!("{}[{}]", lvalue_to_rust(base), expr_to_rust(index))
        }
        LValue::Member { base, field } => format!("{}.{}", lvalue_to_rust(base), field),
    }
}
