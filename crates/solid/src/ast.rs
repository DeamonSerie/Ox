use serde::{Deserialize, Serialize};

/// Type system for the Solidity-like DSL
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Type {
    Address,
    U64,
    U256,
    Uint(u16),
    Int(u16),
    Bytes,
    Bytes32,
    FixedBytes(u8),
    Bool,
    String,
    Named(String),
    Array(Box<Type>),
    Mapping { key: Box<Type>, value: Box<Type> },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ContractKind {
    Contract,
    Interface,
    Library,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Mutability {
    Pure,
    View,
    Payable,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FunctionKind {
    Function,
    Constructor,
    Fallback,
    Receive,
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
    #[serde(rename = "external")]
    External,
}

/// State variable
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Variable {
    pub name: String,
    pub ty: Type,
    pub mutable: bool,
    pub visibility: Visibility,
    pub constant: bool,
    pub immutable: bool,
    pub initializer: Option<Expr>,
}

/// Function parameter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Param {
    pub name: String,
    pub ty: Type,
    pub indexed: bool,
}

/// Function definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Function {
    pub name: String,
    pub kind: FunctionKind,
    pub visibility: Visibility,
    pub mutability: Option<Mutability>,
    pub modifiers: Vec<ModifierInvocation>,
    pub virtual_: bool,
    pub overrides: Vec<String>,
    pub inputs: Vec<Param>,
    pub outputs: Vec<Param>,
    pub body: Block,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModifierInvocation {
    pub name: String,
    pub args: Vec<Expr>,
}

/// Event definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub name: String,
    pub params: Vec<Param>,
    pub indexed: Vec<String>,
    pub anonymous: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Struct {
    pub name: String,
    pub fields: Vec<Param>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Enum {
    pub name: String,
    pub variants: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Modifier {
    pub name: String,
    pub inputs: Vec<Param>,
    pub body: Block,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomError {
    pub name: String,
    pub inputs: Vec<Param>,
}

/// Parsed contract definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contract {
    #[serde(rename = "name")]
    pub name_: String,
    pub kind: ContractKind,
    pub pragma: Option<String>,
    pub imports: Vec<String>,
    #[serde(rename = "parents")]
    pub parents: Vec<String>,
    #[serde(rename = "variables")]
    pub variables: Vec<Variable>,
    #[serde(rename = "functions")]
    pub functions: Vec<Function>,
    #[serde(rename = "events")]
    pub events: Vec<Event>,
    pub structs: Vec<Struct>,
    pub enums: Vec<Enum>,
    pub modifiers: Vec<Modifier>,
    pub errors: Vec<CustomError>,
}

/// Block statements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub statements: Vec<Statement>,
}

/// Statement types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Statement {
    Let {
        name: String,
        ty: Type,
        init: Option<Expr>,
    },
    Assign {
        target: LValue,
        value: Expr,
    },
    If {
        condition: Expr,
        true_block: Block,
        false_block: Option<Block>,
    },
    For {
        init: Option<Box<Statement>>,
        cond: Option<Expr>,
        update: Option<Expr>,
        block: Block,
    },
    While {
        cond: Expr,
        block: Block,
    },
    DoWhile {
        block: Block,
        cond: Expr,
    },
    Break,
    Continue,
    Return(Option<Expr>),
    Emitevent {
        event: String,
        args: Vec<(String, Expr)>,
    },
    Assert {
        condition: Expr,
        message: String,
    },
    Require {
        condition: Expr,
        message: Option<String>,
    },
    Revert {
        error: Option<String>,
        args: Vec<Expr>,
    },
    Placeholder,
    Expression(Expr),
    Block(Block),
}

/// LValue target
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LValue {
    Ident(String),
    Index { base: Box<LValue>, index: Expr },
    Member { base: Box<LValue>, field: String },
}

/// Expression types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Expr {
    LitInt(u64),
    LitNumber(String),
    LitDecimal(String),
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
    Call {
        func: String,
        args: Vec<Expr>,
    },
    Access {
        target: String,
        field: String,
    },
    Index {
        target: Box<Expr>,
        index: Box<Expr>,
    },
    Ternary {
        condition: Box<Expr>,
        true_expr: Box<Expr>,
        false_expr: Box<Expr>,
    },
    Pow(Box<Expr>, Box<Expr>),
    BitAnd(Box<Expr>, Box<Expr>),
    BitOr(Box<Expr>, Box<Expr>),
    BitXor(Box<Expr>, Box<Expr>),
    Shl(Box<Expr>, Box<Expr>),
    Shr(Box<Expr>, Box<Expr>),
    Assign {
        target: Box<Expr>,
        op: String,
        value: Box<Expr>,
    },
    Update {
        target: Box<Expr>,
        increment: bool,
        prefix: bool,
    },
}

/// Address type (20 bytes)
pub type Address = [u8; 20];
