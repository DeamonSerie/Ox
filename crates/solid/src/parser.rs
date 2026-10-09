use pest_derive::Parser;

#[derive(Parser)]
#[grammar = "solidity.pest"]
pub struct SolidParser;

pub use pest::error::Error as PestError;
