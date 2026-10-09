mod ast;
mod parser;
mod codegen;
mod builtins;

use ast::{self as ast_mod, Type, Visibility, Statement, Expr, LValue, Param, Contract, Event};
use pest::error::Error as PestError;
use serde::{Deserialize, Serialize};

/// Parsed Solidity-like contract AST
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contract {
    #[serde(rename = "name")]
    pub name_: String,
    #[serde(rename = "parents")]
    pub parents: Vec<String>,
    #[serde(rename = "variables")]
    pub variables: Vec<ast_mod::Variable>,
    #[serde(rename = "functions")]
    pub functions: Vec<ast_mod::Function>,
    #[serde(rename = "events")]
    pub events: Vec<ast_mod::Event>,
}

/// Parse a Solidity-like contract string into an AST
pub fn parse_contract(input: &str) -> Result<Contract, PestError<Rule>> {
    use crate::parser::SolidParser;
    let pair = SolidParser::parse(Rule::source_unit, input)?;
    // TODO: Convert pest pair to AST
    Ok(Contract {
        name_: "Default".to_string(),
        parents: vec![],
        variables: vec![],
        functions: vec![],
        events: vec![],
    })
}

/// Type checking result
#[derive(Debug)]
pub struct TypeError {
    pub message: String,
}

impl std::fmt::Display for TypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for TypeError {}

/// Compile the contract to Rust code
pub fn compile_to_rust(contract: &Contract) -> String {
    codegen::rust_source(contract)
}

/// Example ERC20-like token contract
pub fn token_contract() -> Contract {
    use Type::*;
    use Visibility::*;

    Contract {
        name_: "Token".to_string(),
        parents: vec![],
        variables: vec![
            ast_mod::Variable {
                name: "name".to_string(),
                ty: Type::String,
                mutable: false,
            },
            ast_mod::Variable {
                name: "symbol".to_string(),
                ty: Type::String,
                mutable: false,
            },
            ast_mod::Variable {
                name: "decimals".to_string(),
                ty: Type::U64,
                mutable: false,
            },
            ast_mod::Variable {
                name: "total_supply".to_string(),
                ty: Type::U256,
                mutable: false,
            },
            ast_mod::Variable {
                name: "balances".to_string(),
                ty: Type::Mapping {
                    key: Box::new(Type::Address),
                    value: Box::new(Type::U256),
                },
                mutable: true,
            },
        ],
        functions: vec![
            ast_mod::Function {
                name: "name".to_string(),
                visibility: Public,
                inputs: vec![],
                outputs: vec![Param {
                    name: "".to_string(),
                    ty: Type::String,
                }],
                body: ast_mod::Block {
                    statements: vec![Statement::Return(Some(Expr::Ident("name".to_string())))],
                },
            },
            ast_mod::Function {
                name: "symbol".to_string(),
                visibility: Public,
                inputs: vec![],
                outputs: vec![Param {
                    name: "".to_string(),
                    ty: Type::String,
                }],
                body: ast_mod::Block {
                    statements: vec![Statement::Return(Some(Expr::Ident("symbol".to_string())))],
                },
            },
        ],
        events: vec![
            ast_mod::Event {
                name: "Transfer".to_string(),
                params: vec![
                    Param {
                        name: "from".to_string(),
                        ty: Type::Address,
                    },
                    Param {
                        name: "to".to_string(),
                        ty: Type::Address,
                    },
                    Param {
                        name: "value".to_string(),
                        ty: Type::U256,
                    },
                ],
                indexed: vec!["from".to_string(), "to".to_string()],
            },
        ],
    }
}
