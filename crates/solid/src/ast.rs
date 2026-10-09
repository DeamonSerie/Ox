use serde::{Deserialize, Serialize};

/// Type system for the Solidity-like DSL
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Type {
    Address,
    U64,
    U256,
    Bool,
    String,
    Array(Box<Type>),
    Mapping { key: Box<Type>, value: Box<Type> },
}

/// Visibility modifiers
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Visibility {
    #[serde(rename = "public")]
    Public,
    #[serde(rename = "internal")]
    Internal,
    #[serde(rename = "private")]
    Private,
}

/// State variable
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Variable {
    pub name: String,
    pub ty: Type,
    pub mutable: bool,
}

/// Function parameter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Param {
    pub name: String,
    pub ty: Type,
}

/// Function definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Function {
    pub name: String,
    pub visibility: Visibility,
    pub inputs: Vec<Param>,
    pub outputs: Vec<Param>,
    pub body: Block,
}

/// Event definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub name: String,
    pub params: Vec<Param>,
    pub indexed: Vec<String>,
}

/// Block statements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub statements: Vec<Statement>,
}

/// Statement types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Statement {
    Let { name: String, ty: Type, init: Option<Expr> },
    Assign { target: LValue, value: Expr },
    If { condition: Expr, true_block: Block, false_block: Option<Block> },
    For { init: Option<Expr>, cond: Expr, update: Option<Expr>, block: Block },
    While { cond: Expr, block: Block },
    Return(Option<Expr>),
    Emitevent { event: String, args: Vec<(String, Expr)> },
    Assert { condition: Expr, message: String },
}

/// LValue target
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LValue {
    Ident(String),
    Index { base: Box<LValue>, index: Expr },
}

/// Expression types
#[derive(Debug, Clone)]
pub enum Expr {
    LitInt(u64),
    LitBool(bool),
    LitString(String),
    Address([u8; 20]),
    Ident(String),
    Add(Box<Expr>, Box<Expr>),
    Sub(Box<Expr>, Box<Expr>),
    Mul(Box<Expr>, Box<Expr>),
    Div(Box<Expr>, Box<Expr>),
    Mod(Box<Expr>, Box<Expr>),
    Eq(Box<Expr>, Box<Expr>),
    Neq(Box<Expr>, Box<Expr>),
    Gt(Box<Expr>, Box<Expr>),
    Lt(Box<Expr>, Box<Expr>),
    Gte(Box<Expr>, Box<Expr>),
    Lte(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    UMinus(Box<Expr>),
    Call { func: String, args: Vec<Expr> },
    Access { target: String, field: String },
}

/// Address type (20 bytes)
pub type Address = [u8; 20];
