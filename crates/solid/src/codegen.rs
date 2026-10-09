use crate::ast::{self, Type, Visibility, Statement, Expr, LValue, Param, Block, Event};

/// Generate Rust source code from a contract AST
pub fn rust_source(contract: &crate::ast::Contract) -> String {
    let name = &contract.name;
    let parents = &contract.parents;
    let vars = &contract.variables;
    let funcs = &contract.functions;
    let events = &contract.events;

    let mut output = String::new();

    // Add license/header
    output.push_str("// Auto-generated from Solidity-like DSL\n");
    output.push_str(&format!("\ncontract {} {{\n", name)));

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
        let outputs: Vec<String> = func
            .outputs
            .iter()
            .map(|p| type_to_rust(&p.ty))
            .collect();

        output.push_str(&format!(
            "    {} fn {}(",
            vis, name
        ));
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
        Type::Bool => "bool".to_string(),
        Type::String => "String".to_string(),
        Type::Array(inner) => format!("Vec<{}>", type_to_rust(inner)),
        Type::Mapping { key, value } => {
            format!("std::collections::HashMap<{}, {}>", type_to_rust(key), type_to_rust(value))
        }
    }
}

/// Convert Visibility to Rust visibility
fn visibility_to_rust(vis: &Visibility) -> String {
    match vis {
        Visibility::Public => "pub",
        Visibility::Internal => "",
        Visibility::Private => "private",
    }
    .to_string()
}

/// Format a statement with indentation
fn format_statement(stmt: &Statement, indent: usize) -> String {
    let spaces = " ".repeat(indent);
    match stmt {
        Statement::Let { name, ty, init } => {
            let init_str = init.as_ref().map_or(String::new(), |e| format!(" = {}", expr_to_rust(e)));
            format!("{}let {}: {} = {};\n", spaces, name, type_to_rust(ty), init_str)
        }
        Statement::Assign { target, value } => {
            let target = match target {
                LValue::Ident(n) => n.clone(),
                LValue::Index { base, index } => format!("{}[{}]", expr_to_rust(base), expr_to_rust(index)),
            };
            format!("{} {} = {};\n", spaces, target, expr_to_rust(value))
        }
        Statement::If { condition, true_block, false_block } => {
            let mut result = format!("{}if {} {{\n", spaces, expr_to_rust(condition)));
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
        Statement::For { init, cond, update, block } => {
            let init_str = init.as_ref().map_or(String::new(), |e| format!("{}", expr_to_rust(e)));
            let cond_str = expr_to_rust(cond);
            let update_str = update.as_ref().map_or(String::new(), |e| format!("{}", expr_to_rust(e)));
            let mut result = format!("{}for (init: {}; {}; update: {}) {{\n", spaces, init_str, cond_str, update_str);
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
        Statement::Return(Some(val)) => format!("{}return {};\n", spaces, expr_to_rust(val)),
        Statement::Return(None) => format!("{}return;\n", spaces),
        Statement::Emitevent { event, args } => {
            let args_str: Vec<String> = args
                .iter()
                .map(|(name, expr)| format!("{} {}", type_to_rust(&Expr::Ident(name.clone())), expr_to_rust(expr)))
                .collect();
            format!("{}emit {}({});\n", spaces, event, args_str.join(", "))
        }
        Statement::Assert { condition, message } => {
            format!("{}assert!({} {}, \"\");\n", spaces, expr_to_rust(condition), message)
        }
    }
}

/// Convert Expr to Rust expression string
fn expr_to_rust(expr: &Expr) -> String {
    match expr {
        Expr::LitInt(n) => n.to_string(),
        Expr::LitBool(b) => b.to_string(),
        Expr::LitString(s) => format!("\"{}\"", s),
        Expr::Address(addr) => {
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
    }
}
