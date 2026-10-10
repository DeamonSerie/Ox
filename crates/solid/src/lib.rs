//! Solidity-inspired contract DSL.
//!
//! The parser and AST cover single-contract source files with pragmas/imports, contract,
//! interface and library definitions, inheritance, state variables, mappings and arrays,
//! functions and special functions, modifiers, events, custom errors, structs, enums,
//! and the common control-flow and expression operators. This is a practical subset, not
//! full Solidity compatibility: symbol-selective imports, multiple top-level contracts,
//! function types, `try`/`catch`, `unchecked`, inline assembly and tuple destructuring are
//! not currently modeled.
//!
//! The native OVM compiler accepts only `u64`/`bool` scalars, scalar state, supported
//! arithmetic and logical expressions, assignments, conditionals, and loops. It rejects
//! constructs without explicit OVM semantics; parsing Solidity-like syntax does not imply
//! that the OVM compiler supports it. No EVM bytecode, ABI, or environment compatibility
//! is provided.

pub mod ast;
mod codegen;
mod ovm_compiler;
mod ovm_validation;
mod parser;

use ast::{
    self as ast_mod, ContractKind, Expr, FunctionKind, Mutability, Param, Statement, Type,
    Visibility,
};

pub use ast::Contract;
pub use ovm_compiler::{compile_contract_to_ovm, compile_function_to_ovm, CompileError};
pub use parser::{PestError, Rule};

/// Parse one Solidity contract, interface, or library definition into an AST.
pub fn parse_contract(input: &str) -> Result<Contract, PestError<Rule>> {
    parser::parse_contract(input)
}

/// Validate that one named contract function uses the supported native OVM subset.
///
/// This performs type, scope, assignment, control-flow, and return-path checks without
/// generating bytecode. Successful validation does not imply EVM compatibility.
pub fn validate_function_for_ovm(
    contract: &Contract,
    function_name: &str,
) -> Result<(), CompileError> {
    let function = contract
        .functions
        .iter()
        .find(|function| function.name == function_name)
        .ok_or_else(|| CompileError::FunctionNotFound(function_name.to_owned()))?;
    ovm_validation::validate_function(contract, function)
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
    use Visibility::*;

    Contract {
        name_: "Token".to_string(),
        kind: ContractKind::Contract,
        pragma: None,
        imports: vec![],
        parents: vec![],
        variables: vec![
            ast_mod::Variable {
                name: "name".to_string(),
                ty: Type::String,
                mutable: false,
                visibility: Visibility::Internal,
                constant: false,
                immutable: false,
                initializer: None,
            },
            ast_mod::Variable {
                name: "symbol".to_string(),
                ty: Type::String,
                mutable: false,
                visibility: Visibility::Internal,
                constant: false,
                immutable: false,
                initializer: None,
            },
            ast_mod::Variable {
                name: "decimals".to_string(),
                ty: Type::U64,
                mutable: false,
                visibility: Visibility::Internal,
                constant: false,
                immutable: false,
                initializer: None,
            },
            ast_mod::Variable {
                name: "total_supply".to_string(),
                ty: Type::U256,
                mutable: false,
                visibility: Visibility::Internal,
                constant: false,
                immutable: false,
                initializer: None,
            },
            ast_mod::Variable {
                name: "balances".to_string(),
                ty: Type::Mapping {
                    key: Box::new(Type::Address),
                    value: Box::new(Type::U256),
                },
                mutable: true,
                visibility: Visibility::Internal,
                constant: false,
                immutable: false,
                initializer: None,
            },
        ],
        functions: vec![
            ast_mod::Function {
                name: "name".to_string(),
                kind: FunctionKind::Function,
                visibility: Public,
                mutability: Some(Mutability::View),
                modifiers: vec![],
                virtual_: false,
                overrides: vec![],
                inputs: vec![],
                outputs: vec![Param {
                    name: "".to_string(),
                    ty: Type::String,
                    indexed: false,
                }],
                body: ast_mod::Block {
                    statements: vec![Statement::Return(Some(Expr::Ident("name".to_string())))],
                },
            },
            ast_mod::Function {
                name: "symbol".to_string(),
                kind: FunctionKind::Function,
                visibility: Public,
                mutability: Some(Mutability::View),
                modifiers: vec![],
                virtual_: false,
                overrides: vec![],
                inputs: vec![],
                outputs: vec![Param {
                    name: "".to_string(),
                    ty: Type::String,
                    indexed: false,
                }],
                body: ast_mod::Block {
                    statements: vec![Statement::Return(Some(Expr::Ident("symbol".to_string())))],
                },
            },
        ],
        events: vec![ast_mod::Event {
            name: "Transfer".to_string(),
            anonymous: false,
            params: vec![
                Param {
                    name: "from".to_string(),
                    ty: Type::Address,
                    indexed: true,
                },
                Param {
                    name: "to".to_string(),
                    ty: Type::Address,
                    indexed: true,
                },
                Param {
                    name: "value".to_string(),
                    ty: Type::U256,
                    indexed: false,
                },
            ],
            indexed: vec!["from".to_string(), "to".to_string()],
        }],
        structs: vec![],
        enums: vec![],
        modifiers: vec![],
        errors: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ast::{ContractKind, FunctionKind};

    #[test]
    fn parses_solidity_core_declarations_and_control_flow() {
        let source = r#"
                pragma solidity ^0.8.20;
                import "base.sol";

                contract Token is Base, Pausable {
                    uint256 public constant CAP = 1000;
                    mapping(address => uint256) private balances;

                    struct Account { address owner; uint64 count; }
                    enum State { Active, Paused }
                    event Transfer(address indexed from, address indexed to, uint256 amount);
                    error Unauthorized(address caller);

                    modifier onlyOwner(address expected) {
                        require(msg.sender == expected, "not owner");
                        _;
                    }

                    constructor(address initialOwner) payable {
                        owner = initialOwner;
                    }

                    function transfer(address to, uint256 amount)
                        external onlyOwner(owner) returns (bool)
                    {
                        require(to != address(0), "zero address");
                        uint256 value = amount;
                        if (value > balances[msg.sender]) {
                            revert Unauthorized(msg.sender);
                        } else {
                            balances[msg.sender] -= value;
                        }
                        for (uint256 i = 0; i < 2; i++) {
                            balances[to]++;
                        }
                        do { balances[to]--; } while (false);
                        emit Transfer(msg.sender, to, value);
                        return true;
                    }
                }
            "#;

        let contract = parse_contract(source).expect("valid Solidity subset");
        assert_eq!(contract.name_, "Token");
        assert_eq!(contract.kind, ContractKind::Contract);
        assert!(contract.pragma.as_deref().unwrap().contains("^0.8.20"));
        assert_eq!(contract.imports, ["base.sol"]);
        assert_eq!(contract.parents, ["Base", "Pausable"]);
        assert_eq!(contract.variables.len(), 2);
        assert!(contract.variables[0].constant);
        assert_eq!(contract.structs[0].fields.len(), 2);
        assert_eq!(contract.enums[0].variants, ["Active", "Paused"]);
        assert_eq!(contract.events[0].indexed, ["from", "to"]);
        assert_eq!(contract.errors[0].name, "Unauthorized");
        assert_eq!(contract.modifiers[0].name, "onlyOwner");
        assert_eq!(contract.functions[0].kind, FunctionKind::Constructor);
        let transfer = &contract.functions[1];
        assert_eq!(transfer.visibility, Visibility::External);
        assert_eq!(transfer.modifiers[0].name, "onlyOwner");
        assert_eq!(transfer.modifiers[0].args.len(), 1);
        assert!(matches!(
            transfer.body.statements[0],
            Statement::Require { .. }
        ));
        assert!(matches!(transfer.body.statements[2], Statement::If { .. }));
        assert!(matches!(transfer.body.statements[3], Statement::For { .. }));
        assert!(matches!(
            transfer.body.statements[4],
            Statement::DoWhile { .. }
        ));
        assert!(matches!(
            transfer.body.statements[5],
            Statement::Emitevent { .. }
        ));
    }

    #[test]
    fn rejects_invalid_solidity_syntax() {
        assert!(parse_contract("contract {").is_err());
        assert!(parse_contract("contract MissingSemicolon {} trailing").is_err());
    }

    #[test]
    fn validates_the_native_ovm_subset_before_compilation() {
        let valid = parse_contract(
            "contract C { function test(bool condition) public pure returns (bool) { return condition; } }",
        )
        .unwrap();
        assert!(validate_function_for_ovm(&valid, "test").is_ok());
        assert!(matches!(
            validate_function_for_ovm(&valid, "missing"),
            Err(CompileError::FunctionNotFound(_))
        ));

        let invalid = parse_contract(
            "contract C { function test() public pure returns (bool) { return 1; } }",
        )
        .unwrap();
        assert!(matches!(
            validate_function_for_ovm(&invalid, "test"),
            Err(CompileError::Unsupported(_))
        ));
    }

    #[test]
    fn parses_solidity_types_and_expression_precedence() {
        let contract = parse_contract(
            r#"
                interface Math {
                    uint8[] values;
                    bytes32 root;
                    int128 offset;

                    function calculate(uint256 a, uint256 b)
                        external pure returns (uint256)
                    {
                        for (;;) { break; }
                        return a + b * 2 >= 3 && true ? a << 1 : b ** 2;
                    }
                }
            "#,
        )
        .expect("valid Solidity type and expression subset");

        assert_eq!(contract.kind, ContractKind::Interface);
        assert!(matches!(contract.variables[0].ty, Type::Array(_)));
        assert_eq!(contract.variables[1].ty, Type::Bytes32);
        assert_eq!(contract.variables[2].ty, Type::Int(128));
        let function = &contract.functions[0];
        assert_eq!(function.mutability, Some(Mutability::Pure));
        assert!(matches!(
            function.body.statements[0],
            Statement::For { cond: None, .. }
        ));
        let Statement::Return(Some(expression)) = &function.body.statements[1] else {
            panic!("expected returned expression");
        };
        assert!(matches!(expression, Expr::Ternary { .. }));
    }
}
