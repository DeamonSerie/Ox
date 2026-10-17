//! Opcode-text front end for `.solid` files.
//!
//! A `.solid` file may begin with the literal `%OPCODE_FILE%` marker (on the first
//! non-blank, non-`//` line). When present, the file body is parsed as raw OVM
//! opcode text rather than Solid-lang, and compiled straight into a canonical
//! [`ContractArtifact`] bytes. The marker is a source convention of `oxydome-solid`;
//! it is not a node-level file reader (nodes deploy pre-compiled artifacts).

use crate::ovm_compiler::{CompileError, CompiledSolid};
use oxydome_crypto::Hash;
use oxydome_ovm::{ContractArtifact, ContractFunction, ContractValueType, Instruction, Program};

/// The exact token that selects the opcode-text front end when it appears on the
/// first non-blank, non-comment line of a `.solid` source. Trailing text (e.g.
/// `%OPCODE_FILE% foo`) must not match — such a file falls through to Solid mode
/// and the stray marker is rejected by [`crate::compile_source_to_ovm`].
pub(crate) const MARKER: &str = "%OPCODE_FILE%";

/// How [`crate::compile_source_to_ovm`] classified a source string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Detect {
    OpcodeFile,
    SolidMode,
}

/// Inspect leading non-blank, non-`//` content to decide whether `src` is an
/// opcode-text file. The first such line must equal [`MARKER`] exactly.
pub(crate) fn detect_marker(src: &str) -> Detect {
    let cleaned = strip_comments(src);
    for line in cleaned.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        return if trimmed == MARKER {
            Detect::OpcodeFile
        } else {
            Detect::SolidMode
        };
    }
    Detect::SolidMode
}

/// Compile an opcode-text `.solid` source (with the `%OPCODE_FILE%` marker at the
/// top) into a [`CompiledSolid`] carrying the canonical `ContractArtifact` bytes
/// and a `None` DAO policy.
pub(crate) fn compile_opcode_file(
    src: &str,
    source_hash: Option<Hash>,
    asset_manifest_hash: Option<Hash>,
) -> Result<CompiledSolid, CompileError> {
    let cleaned = strip_comments(src);
    let lines = body_lines(&cleaned);
    let mut functions = parse_functions(&lines)?;
    functions.sort_by(|left, right| left.name.cmp(&right.name));
    let artifact = ContractArtifact {
        source_hash,
        asset_manifest_hash,
        functions,
    };
    Ok(CompiledSolid {
        contract_artifact: artifact.encode()?,
        dao_policy: None,
        timer_config: None,
        pegged_config: None,
        liquidity_pool_config: None,
    })
}

/// Remove `//` line comments and `/* ... */` block comments while preserving the
/// newline structure, so downstream line-oriented parsing stays line-accurate.
/// This mirrors the `COMMENT` rule of `solidity.pest`.
fn strip_comments(src: &str) -> String {
    let chars: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    let mut in_line = false;
    let mut in_block = false;
    while i < chars.len() {
        let c = chars[i];
        if in_line {
            if c == '\n' {
                in_line = false;
                out.push('\n');
            }
            i += 1;
            continue;
        }
        if in_block {
            if c == '*' && i + 1 < chars.len() && chars[i + 1] == '/' {
                in_block = false;
                i += 2;
                continue;
            }
            if c == '\n' {
                out.push('\n');
            }
            i += 1;
            continue;
        }
        if c == '/' && i + 1 < chars.len() {
            if chars[i + 1] == '/' {
                in_line = true;
                i += 2;
                continue;
            }
            if chars[i + 1] == '*' {
                in_block = true;
                i += 2;
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

/// Collect the opcode body: skip the leading marker line (and any leading blank
/// lines before it), then return every remaining non-blank, trimmed line.
fn body_lines(cleaned: &str) -> Vec<String> {
    let mut marker_seen = false;
    let mut out = Vec::new();
    for line in cleaned.lines() {
        let trimmed = line.trim();
        if !marker_seen {
            if trimmed.is_empty() {
                continue;
            }
            marker_seen = true;
            continue;
        }
        if trimmed.is_empty() {
            continue;
        }
        out.push(trimmed.to_string());
    }
    out
}

/// Per-function accumulator used while scanning the body.
struct FunctionAccumulator {
    name: String,
    args: Option<u8>,
    locals: Option<u8>,
    inputs: Vec<ContractValueType>,
    output: Option<ContractValueType>,
    instructions: Vec<Instruction>,
}

/// Parse every `function` block in the body into [`ContractFunction`]s.
fn parse_functions(lines: &[String]) -> Result<Vec<ContractFunction>, CompileError> {
    let mut functions = Vec::new();
    let mut current: Option<FunctionAccumulator> = None;
    for line in lines {
        let first = line.split_whitespace().next();
        if first == Some("function") {
            if let Some(acc) = current.take() {
                functions.push(finalize_function(
                    acc.name,
                    acc.args,
                    acc.locals,
                    acc.inputs,
                    acc.output,
                    acc.instructions,
                )?);
            }
            let mut tokens = line.split_whitespace();
            tokens.next();
            let name = tokens
                .next()
                .ok_or_else(|| {
                    CompileError::Unsupported("`function` declaration is missing a name".into())
                })?
                .to_string();
            if tokens.next().is_some() {
                return Err(CompileError::Unsupported(format!(
                    "`function {name}` has extra tokens; expected just `function <name>`"
                )));
            }
            current = Some(FunctionAccumulator {
                name,
                args: None,
                locals: None,
                inputs: Vec::new(),
                output: None,
                instructions: Vec::new(),
            });
        } else if current.is_none() {
            return Err(CompileError::Unsupported(format!(
                "opcode file must start with `function <name>`, found: {line}"
            )));
        } else {
            let acc = current.as_mut().expect("current function exists");
            if let Some((key, value)) = parse_header_line(line) {
                apply_header(acc, key, value)?;
            } else {
                acc.instructions.push(parse_instruction(line)?);
            }
        }
    }
    if let Some(acc) = current {
        functions.push(finalize_function(
            acc.name,
            acc.args,
            acc.locals,
            acc.inputs,
            acc.output,
            acc.instructions,
        )?);
    }
    Ok(functions)
}

/// Finalise one function: require `args`, default `locals` to 0, validate the
/// name, then encode the [`Program`] into the function's `code` bytes. The
/// surrounding `ContractArtifact::encode` re-runs `verify`, enforcing the
/// `argument_count == inputs.len() + AUTHORITY_WORD_COUNT` invariant and jump
/// bounds, so the parser stays thin.
fn finalize_function(
    name: String,
    args: Option<u8>,
    locals: Option<u8>,
    inputs: Vec<ContractValueType>,
    output: Option<ContractValueType>,
    instructions: Vec<Instruction>,
) -> Result<ContractFunction, CompileError> {
    let argument_count = args.ok_or_else(|| {
        CompileError::Unsupported(format!(
            "function `{name}` is missing the required `args:` header"
        ))
    })?;
    let local_count = locals.unwrap_or(0);
    if !oxydome_ovm::valid_function_name(&name) {
        return Err(CompileError::Unsupported(format!(
            "invalid OVM function name `{name}`"
        )));
    }
    let program = Program {
        argument_count,
        local_count,
        instructions,
    };
    let code = program.encode()?;
    Ok(ContractFunction {
        name,
        inputs,
        output,
        code,
    })
}

/// Recognise a header line as `key: value` where `key` is one of
/// `args`/`locals`/`inputs`/`output`. Returns the canonical key and the trimmed
/// remainder of the line (the value).
fn parse_header_line(line: &str) -> Option<(&'static str, &str)> {
    let first = line.split_whitespace().next()?;
    let stem = first.strip_suffix(':')?;
    let key: &'static str = match stem {
        "args" => "args",
        "locals" => "locals",
        "inputs" => "inputs",
        "output" => "output",
        _ => return None,
    };
    let value = line[first.len()..].trim();
    Some((key, value))
}

fn apply_header(
    acc: &mut FunctionAccumulator,
    key: &'static str,
    value: &str,
) -> Result<(), CompileError> {
    match key {
        "args" => {
            acc.args = Some(parse_int::<u8>(value)?);
        }
        "locals" => {
            acc.locals = Some(parse_int::<u8>(value)?);
        }
        "inputs" => {
            for token in value.split_whitespace() {
                acc.inputs.push(parse_value_type(token)?);
            }
        }
        "output" => {
            if value.is_empty() {
                acc.output = None;
            } else {
                acc.output = Some(parse_value_type(value)?);
            }
        }
        _ => unreachable!("parse_header_line only yields known keys"),
    }
    Ok(())
}

/// Parse one instruction line into an [`Instruction`], validating operand count
/// and width. Mnemonics are matched case-insensitively (upper-cased for the table).
fn parse_instruction(line: &str) -> Result<Instruction, CompileError> {
    let mut parts = line.split_whitespace();
    let mnemonic = parts
        .next()
        .ok_or_else(|| CompileError::Unsupported("empty instruction line".into()))?;
    let rest: Vec<&str> = parts.collect();
    let mnem = mnemonic.to_ascii_uppercase();
    match mnem.as_str() {
        "PUSH" => {
            expect_operands(&mnem, &rest, 1)?;
            Ok(Instruction::Push(parse_int::<u64>(rest[0])?))
        }
        "LOADARG" => {
            expect_operands(&mnem, &rest, 1)?;
            Ok(Instruction::LoadArg(parse_int::<u8>(rest[0])?))
        }
        "LOADLOCAL" => {
            expect_operands(&mnem, &rest, 1)?;
            Ok(Instruction::LoadLocal(parse_int::<u8>(rest[0])?))
        }
        "STORELOCAL" => {
            expect_operands(&mnem, &rest, 1)?;
            Ok(Instruction::StoreLocal(parse_int::<u8>(rest[0])?))
        }
        "LOADSTORAGE" => {
            expect_operands(&mnem, &rest, 1)?;
            Ok(Instruction::LoadStorage(parse_int::<u64>(rest[0])?))
        }
        "STORESTORAGE" => {
            expect_operands(&mnem, &rest, 1)?;
            Ok(Instruction::StoreStorage(parse_int::<u64>(rest[0])?))
        }
        "ADD" => {
            expect_operands(&mnem, &rest, 0)?;
            Ok(Instruction::Add)
        }
        "SUB" => {
            expect_operands(&mnem, &rest, 0)?;
            Ok(Instruction::Sub)
        }
        "MUL" => {
            expect_operands(&mnem, &rest, 0)?;
            Ok(Instruction::Mul)
        }
        "DIV" => {
            expect_operands(&mnem, &rest, 0)?;
            Ok(Instruction::Div)
        }
        "MOD" => {
            expect_operands(&mnem, &rest, 0)?;
            Ok(Instruction::Mod)
        }
        "EQ" => {
            expect_operands(&mnem, &rest, 0)?;
            Ok(Instruction::Equal)
        }
        "LT" => {
            expect_operands(&mnem, &rest, 0)?;
            Ok(Instruction::LessThan)
        }
        "GT" => {
            expect_operands(&mnem, &rest, 0)?;
            Ok(Instruction::GreaterThan)
        }
        "AND" => {
            expect_operands(&mnem, &rest, 0)?;
            Ok(Instruction::And)
        }
        "OR" => {
            expect_operands(&mnem, &rest, 0)?;
            Ok(Instruction::Or)
        }
        "NOT" => {
            expect_operands(&mnem, &rest, 0)?;
            Ok(Instruction::Not)
        }
        "XOR" => {
            expect_operands(&mnem, &rest, 0)?;
            Ok(Instruction::BitXor)
        }
        "SHL" => {
            expect_operands(&mnem, &rest, 0)?;
            Ok(Instruction::Shl)
        }
        "SHR" => {
            expect_operands(&mnem, &rest, 0)?;
            Ok(Instruction::Shr)
        }
        "JUMP" => {
            expect_operands(&mnem, &rest, 1)?;
            Ok(Instruction::Jump(parse_int::<u32>(rest[0])?))
        }
        "JUMPIF" => {
            expect_operands(&mnem, &rest, 1)?;
            Ok(Instruction::JumpIfFalse(parse_int::<u32>(rest[0])?))
        }
        "EMIT" => {
            expect_operands(&mnem, &rest, 1)?;
            Ok(Instruction::Emit(parse_int::<u32>(rest[0])?))
        }
        "XCALL" => {
            expect_operands(&mnem, &rest, 1)?;
            Ok(Instruction::XCall {
                arg_count: parse_int::<u16>(rest[0])?,
            })
        }
        "READREPLY" => {
            expect_operands(&mnem, &rest, 0)?;
            Ok(Instruction::ReadReply)
        }
        "RETURN" => {
            expect_operands(&mnem, &rest, 0)?;
            Ok(Instruction::Return)
        }
        "REVERT" => {
            expect_operands(&mnem, &rest, 0)?;
            Ok(Instruction::Revert)
        }
        "DATASIZE" => {
            expect_operands(&mnem, &rest, 0)?;
            Ok(Instruction::DataSize)
        }
        "LOADDATA" => {
            expect_operands(&mnem, &rest, 1)?;
            Ok(Instruction::LoadData(parse_int::<u64>(rest[0])?))
        }
        "STOREDATA" => {
            expect_operands(&mnem, &rest, 1)?;
            Ok(Instruction::StoreData(parse_int::<u64>(rest[0])?))
        }
        _ => Err(CompileError::Unsupported(format!(
            "unknown OVM mnemonic `{mnemonic}`"
        ))),
    }
}

fn expect_operands(mnemonic: &str, rest: &[&str], expected: usize) -> Result<(), CompileError> {
    if rest.len() != expected {
        return Err(CompileError::Unsupported(format!(
            "`{mnemonic}` expects {expected} operand{}, found {}",
            if expected == 1 { "" } else { "s" },
            rest.len()
        )));
    }
    Ok(())
}

/// Parse a Rust-style integer literal (decimal or `0x` hex, with optional `_`
/// separators) into the widest needed type, then narrow to `T`, rejecting
/// overflow.
fn parse_int<T: TryFrom<u64>>(raw: &str) -> Result<T, CompileError> {
    let normalized = raw.trim().replace('_', "");
    let value: u64 = if let Some(hex) = normalized
        .strip_prefix("0x")
        .or_else(|| normalized.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).map_err(|error| {
            CompileError::Unsupported(format!("invalid hex integer `{raw}`: {error}"))
        })?
    } else {
        normalized.parse::<u64>().map_err(|error| {
            CompileError::Unsupported(format!("invalid integer `{raw}`: {error}"))
        })?
    };
    T::try_from(value).map_err(|_| {
        CompileError::Unsupported(format!("integer `{raw}` is out of range for the operand"))
    })
}

fn parse_value_type(raw: &str) -> Result<ContractValueType, CompileError> {
    match raw {
        "u64" => Ok(ContractValueType::U64),
        "bool" => Ok(ContractValueType::Bool),
        other => Err(CompileError::Unsupported(format!(
            "unsupported value type `{other}`; expected `u64` or `bool`"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxydome_ovm::{execute, fn_selector, ContractArtifact as Artifact, Program as Prog};
    use std::collections::BTreeMap;

    const EXAMPLE: &str = "\
// A pure adder: f(a,b) = a + b  (authority words 0..3, inputs at arg slots 4,5)
%OPCODE_FILE%

function add
args: 6
locals: 0
inputs: u64 u64
output: u64
LOADARG 4
LOADARG 5
ADD
RETURN
";

    #[test]
    fn detects_marker_opcode_mode_with_leading_blanks_and_comments() {
        assert_eq!(detect_marker(EXAMPLE), Detect::OpcodeFile);
        assert_eq!(
            detect_marker(
                "\n\n// leading comment\n   \n%OPCODE_FILE%\nfunction f\nargs: 4\nRETURN\n"
            ),
            Detect::OpcodeFile
        );
    }

    #[test]
    fn detects_marker_solid_mode_and_rejects_misplaced_marker() {
        assert_eq!(detect_marker("contract C { }"), Detect::SolidMode);
        assert_eq!(
            detect_marker("%OPCODE_FILE% foo\nfunction f\nargs: 4\nRETURN\n"),
            Detect::SolidMode
        );
        let misplaced = "%OPCODE_FILE% foo\nfunction f\nargs: 4\nlocals: 0\nPUSH 1\nRETURN\n";
        assert!(matches!(
            crate::compile_source_to_ovm(misplaced, None, None),
            Err(CompileError::Unsupported(_))
        ));
    }

    #[test]
    fn example_program_round_trips_and_executes() {
        let compiled = crate::compile_source_to_ovm(EXAMPLE, None, None).unwrap();
        let artifact = Artifact::decode(&compiled.contract_artifact).unwrap();
        assert_eq!(compiled.dao_policy, None);
        let function = artifact.function("add").unwrap();
        assert_eq!(
            function.inputs,
            vec![ContractValueType::U64, ContractValueType::U64]
        );
        assert_eq!(function.output, Some(ContractValueType::U64));
        let program = Prog::decode(&function.code).unwrap();
        assert_eq!(program.argument_count, 6);
        assert_eq!(
            program.instructions,
            vec![
                Instruction::LoadArg(4),
                Instruction::LoadArg(5),
                Instruction::Add,
                Instruction::Return,
            ]
        );
        let execution = execute(&program, &[0, 0, 0, 0, 7, 9], &BTreeMap::new(), 100).unwrap();
        assert_eq!(execution.return_value, Some(16));
    }

    #[test]
    fn every_mnemonic_parses_to_the_expected_instruction() {
        let cases: &[(&str, Instruction)] = &[
            ("PUSH 42", Instruction::Push(42)),
            ("PUSH 0xff", Instruction::Push(255)),
            ("PUSH 1_000", Instruction::Push(1000)),
            ("LOADARG 0", Instruction::LoadArg(0)),
            ("LOADLOCAL 1", Instruction::LoadLocal(1)),
            ("STORELOCAL 2", Instruction::StoreLocal(2)),
            ("LOADSTORAGE 3", Instruction::LoadStorage(3)),
            ("STORESTORAGE 4", Instruction::StoreStorage(4)),
            ("ADD", Instruction::Add),
            ("SUB", Instruction::Sub),
            ("MUL", Instruction::Mul),
            ("DIV", Instruction::Div),
            ("MOD", Instruction::Mod),
            ("EQ", Instruction::Equal),
            ("LT", Instruction::LessThan),
            ("GT", Instruction::GreaterThan),
            ("AND", Instruction::And),
            ("OR", Instruction::Or),
            ("NOT", Instruction::Not),
            ("XOR", Instruction::BitXor),
            ("SHL", Instruction::Shl),
            ("SHR", Instruction::Shr),
            ("JUMP 0", Instruction::Jump(0)),
            ("JUMPIF 1", Instruction::JumpIfFalse(1)),
            ("EMIT 5", Instruction::Emit(5)),
            ("XCALL 0", Instruction::XCall { arg_count: 0 }),
            ("XCALL 2", Instruction::XCall { arg_count: 2 }),
            ("READREPLY", Instruction::ReadReply),
            ("RETURN", Instruction::Return),
            ("REVERT", Instruction::Revert),
            ("DATASIZE", Instruction::DataSize),
            ("LOADDATA 0", Instruction::LoadData(0)),
            ("STOREDATA 8", Instruction::StoreData(8)),
        ];
        for (line, expected) in cases {
            assert_eq!(
                parse_instruction(line),
                Ok(expected.clone()),
                "failed to parse `{line}`"
            );
        }
        assert!(parse_instruction("BOGUS").is_err());
        assert!(parse_instruction("PUSH 99999999999999999999999").is_err());
        assert!(parse_instruction("PUSH 1 2").is_err());
    }

    #[test]
    fn rejects_operand_width_overflow() {
        assert!(parse_instruction("LOADARG 300").is_err());
        assert!(parse_instruction("LOADLOCAL 256").is_err());
        assert!(parse_instruction("JUMP 5000000000").is_err());
        assert!(parse_instruction("XCALL 70000").is_err());
    }

    #[test]
    fn invalid_jump_target_is_rejected_by_program_verify() {
        let src = "%OPCODE_FILE%\n\nfunction bad\nargs: 4\nlocals: 0\nJUMP 99\nRETURN\n";
        let error = crate::compile_source_to_ovm(src, None, None).unwrap_err();
        assert!(matches!(error, CompileError::Bytecode(_)), "got {error:?}");
    }

    #[test]
    fn arg_count_mismatch_is_rejected_at_encode() {
        // args: 6 but inputs declares 3 u64s -> 6 != 3 + 4, rejected by Artifact::verify.
        let src = "%OPCODE_FILE%\n\nfunction f\nargs: 6\nlocals: 0\ninputs: u64 u64 u64\noutput: u64\nLOADARG 6\nRETURN\n";
        let error = crate::compile_source_to_ovm(src, None, None).unwrap_err();
        assert!(matches!(error, CompileError::Bytecode(_)), "got {error:?}");
    }

    #[test]
    fn two_function_opcode_file_builds_canonical_artifact() {
        let src = "\
%OPCODE_FILE%

function beta
args: 4
locals: 0
PUSH 2
RETURN

function alpha
args: 4
locals: 0
PUSH 1
RETURN
";
        let compiled = crate::compile_source_to_ovm(src, None, None).unwrap();
        let artifact = Artifact::decode(&compiled.contract_artifact).unwrap();
        assert_eq!(
            artifact
                .functions
                .iter()
                .map(|f| f.name.as_str())
                .collect::<Vec<_>>(),
            vec!["alpha", "beta"]
        );
        let alpha_selector = fn_selector("alpha");
        let beta_selector = fn_selector("beta");
        assert!(artifact.function_by_selector(alpha_selector).is_some());
        assert!(artifact.function_by_selector(beta_selector).is_some());
        let alpha_program = Prog::decode(&artifact.function("alpha").unwrap().code).unwrap();
        assert_eq!(
            execute(&alpha_program, &[0, 0, 0, 0], &BTreeMap::new(), 100)
                .unwrap()
                .return_value,
            Some(1)
        );
    }

    #[test]
    fn comments_are_stripped_before_parsing() {
        let src = "\
// header comment
%OPCODE_FILE%
/* block
comment */
function add
args: 6 // trailing comment
locals: 0
inputs: u64 u64
output: u64
LOADARG 4 // load a
LOADARG 5 // load b
ADD
RETURN
";
        let compiled = crate::compile_source_to_ovm(src, None, None).unwrap();
        let artifact = Artifact::decode(&compiled.contract_artifact).unwrap();
        let program = Prog::decode(&artifact.function("add").unwrap().code).unwrap();
        assert_eq!(program.argument_count, 6);
        assert_eq!(
            execute(&program, &[0, 0, 0, 0, 7, 9], &BTreeMap::new(), 100)
                .unwrap()
                .return_value,
            Some(16)
        );
    }

    #[test]
    fn compile_source_to_ovm_falls_back_to_solid_path_without_marker() {
        // A regular Solid source has no marker; it must compile via the existing path.
        let src = "contract C { function add(uint64 a, uint64 b) public pure returns (uint64) { return a + b; } }";
        let compiled = crate::compile_source_to_ovm(src, None, None).unwrap();
        assert!(compiled.dao_policy.is_none());
        let artifact = Artifact::decode(&compiled.contract_artifact).unwrap();
        assert_eq!(artifact.functions.len(), 1);
        assert_eq!(artifact.function("add").unwrap().inputs.len(), 2);
    }
}
