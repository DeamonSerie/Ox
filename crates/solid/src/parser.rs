use pest::Parser;
use pest_derive::Parser;

#[derive(Parser)]
#[grammar = "solidity.pest"]
pub struct SolidParser;

pub use pest::error::Error as PestError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rule {
    SourceUnit,
    Pragma,
    Import,
    ContractDefinition,
    Visibility,
    FunctionDefinition,
    Parameter,
    VariableDeclaration,
    EventDeclaration,
    Identifier,
    Number,
    StringLiteral,
    AddressLiteral,
    TypeName,
    Block,
    Statement,
    ForStatement,
    WhileStatement,
    IfStatement,
    Return,
    Emitevent,
    Assert,
    Eq,
    NEq,
    GT,
    LT,
    GTE,
    LTE,
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    And,
    Or,
    Not,
    Call,
    ParenOpen,
    ParenClose,
    LBrace,
    RBrace,
    LBracket,
    RBracket,
    Comma,
    Colon,
    Arrow,
    This,
    Super,
    Mapping,
    ArrayType,
    FunctionSignature,
}
