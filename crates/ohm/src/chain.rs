//! The node-side OHM ledger: private UTXO state re-derived from anchored [`OhmBlock`]s.

use crate::{
    ohm_genesis_hash, ohm_state_root, Amount, Hash, OhmBlock, OhmContract, OhmInput, OhmOutput,
    OhmTransaction, OhmUtxoEntry, OutPoint, PublicKey,
};
use oxydome_core::{OvmAction, OvmFailureCode};
use oxydome_crypto::KeyPair;
use std::collections::BTreeMap;

/// The result of simulating an OHM-hosted contract call (never mutates the ledger).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OhmCallOutcome {
    pub failure: Option<OvmFailureCode>,
    pub gas_used: u64,
    pub return_value: Option<u64>,
    pub logs: Vec<oxydome_ovm::Log>,
}

/// Maps an OVM execution error to its stable, consensus-visible failure code.
fn failure_code(error: oxydome_ovm::VmError) -> OvmFailureCode {
    use oxydome_ovm::VmError;
    match error {
        VmError::Reverted => OvmFailureCode::Reverted,
        VmError::OutOfGas => OvmFailureCode::OutOfGas,
        VmError::ArithmeticOverflow => OvmFailureCode::ArithmeticOverflow,
        VmError::DivisionByZero => OvmFailureCode::DivisionByZero,
        VmError::ArgumentCount => OvmFailureCode::ArgumentCount,
        VmError::MissingReturn => OvmFailureCode::MissingReturn,
        VmError::StorageLimitExceeded => OvmFailureCode::StorageLimitExceeded,
        VmError::StackUnderflow => OvmFailureCode::StackUnderflow,
        VmError::StackOverflow => OvmFailureCode::StackOverflow,
        VmError::InvalidLocal => OvmFailureCode::InvalidLocal,
        VmError::InvalidBytecode | VmError::ProgramTooLarge | VmError::InvalidProgram => {
            OvmFailureCode::InvalidProgram
        }
    }
}

/// Errors produced while validating or applying OHM blocks and transactions.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OhmError {
    #[error("OHM block belongs to a different OHM")]
    WrongOhm,
    #[error("OHM block height {0} does not follow {1}")]
    BadHeight(u64, u64),
    #[error("OHM block does not link to the current head")]
    BadPrevHash,
    #[error("OHM block is not signed by the OHM maintainer")]
    BadMaintainer,
    #[error("OHM block transaction root does not match its body")]
    BadTxRoot,
    #[error("OHM block fee total {0} does not equal the summed transaction fees {1}")]
    BadFeeTotal(Amount, Amount),
    #[error("OHM block state root {0:?} does not match the computed root {1:?}")]
    BadStateRoot(Hash, Hash),
    #[error("OHM block has too many transactions")]
    TooManyTransactions,
    #[error("OHM transaction {0} invalid: {1}")]
    BadTransaction(usize, String),
    #[error("OHM input {0:?} does not exist or is already spent")]
    MissingInput(OutPoint),
    #[error("OHM input {0:?} owner does not match the referenced output")]
    InputOwnerMismatch(OutPoint),
    #[error("OHM transaction does not conserve value")]
    Conservation,
    #[error("OHM amount overflow")]
    Overflow,
    #[error("OHM amount underflow")]
    Underflow,
    #[error("OHM OVM action is invalid: {0}")]
    Ovm(String),
    #[error("OHM OVM deployment collides with an existing contract")]
    OvmContractCollision,
    #[error("OHM OVM contract limit reached")]
    OvmContractLimit,
}

/// The materialised result of applying a batch of OHM transactions.
struct LedgerDelta {
    utxos: BTreeMap<Hash, OhmUtxoEntry>,
    contracts: BTreeMap<Hash, OhmContract>,
    supply: Amount,
    fee_total: Amount,
}

/// A node's private view of a single OHM chain, re-derived from its blocks.
#[derive(Debug, Clone)]
pub struct OhmLedger {
    pub ohm_id: Hash,
    pub maintainer: PublicKey,
    pub genesis_supply: Amount,
    pub supply: Amount,
    pub height: u64,
    pub block_hash: Hash,
    pub state_root: Hash,
    pub utxos: BTreeMap<Hash, OhmUtxoEntry>,
    /// OVM contracts hosted privately by this OHM, keyed by contract id.
    pub contracts: BTreeMap<Hash, OhmContract>,
    blocks: Vec<OhmBlock>,
    roots: BTreeMap<u64, Hash>,
}

impl OhmLedger {
    /// Builds the height-0 ledger from an OHM's genesis outputs.
    ///
    /// `genesis_op_id` is the id of the creating [`crate::OhmOperation`]; genesis outpoints are
    /// derived exactly as the Ox state machine derives them so both views agree.
    pub fn from_genesis(
        ohm_id: Hash,
        maintainer: PublicKey,
        genesis_outputs: &[OhmOutput],
        genesis_op_id: Hash,
    ) -> Self {
        let mut utxos = BTreeMap::new();
        for (i, output) in genesis_outputs.iter().enumerate() {
            let outpoint = OutPoint::new(genesis_op_id, i as u32);
            let entry = OhmUtxoEntry::new(outpoint, output.clone(), 0);
            utxos.insert(entry.key(), entry);
        }
        let supply = genesis_outputs.iter().map(|o| o.amount).sum();
        let contracts = BTreeMap::new();
        let state_root = ohm_state_root(&utxos, &contracts);
        let block_hash = ohm_genesis_hash(&ohm_id);
        let mut roots = BTreeMap::new();
        roots.insert(0u64, state_root);
        Self {
            ohm_id,
            maintainer,
            genesis_supply: supply,
            supply,
            height: 0,
            block_hash,
            state_root,
            utxos,
            contracts,
            blocks: Vec::new(),
            roots,
        }
    }

    /// The stored blocks, ordered by height.
    pub fn blocks(&self) -> &[OhmBlock] {
        &self.blocks
    }

    /// The state root committed at `height`, if the ledger has applied it.
    pub fn root_at(&self, height: u64) -> Option<Hash> {
        self.roots.get(&height).copied()
    }

    /// The block hash committed at `height` (the genesis hash at height 0).
    pub fn hash_at(&self, height: u64) -> Option<Hash> {
        if height == 0 {
            return Some(ohm_genesis_hash(&self.ohm_id));
        }
        self.blocks
            .iter()
            .find(|b| b.header.height == height)
            .map(OhmBlock::hash)
    }

    /// Verifies `block` against the current ledger without mutating it.
    pub fn verify_block(&self, block: &OhmBlock) -> Result<(), OhmError> {
        self.check_continuity(block)?;
        if block.transactions.len() > crate::MAX_OHM_BLOCK_TXS {
            return Err(OhmError::TooManyTransactions);
        }
        let delta = self.apply_transactions(&block.transactions)?;
        if delta.fee_total != block.header.fee_total {
            return Err(OhmError::BadFeeTotal(
                block.header.fee_total,
                delta.fee_total,
            ));
        }
        let root = ohm_state_root(&delta.utxos, &delta.contracts);
        if root != block.header.state_root {
            return Err(OhmError::BadStateRoot(block.header.state_root, root));
        }
        Ok(())
    }

    /// Applies `block`, advancing the ledger. Fails (without mutation) on any inconsistency.
    pub fn apply_block(&mut self, block: &OhmBlock) -> Result<(), OhmError> {
        self.verify_block(block)?;
        let delta = self.apply_transactions(&block.transactions)?;
        let root = ohm_state_root(&delta.utxos, &delta.contracts);
        self.utxos = delta.utxos;
        self.contracts = delta.contracts;
        self.supply = delta.supply;
        self.height = block.header.height;
        self.block_hash = block.hash();
        self.state_root = root;
        self.roots.insert(self.height, root);
        self.blocks.push(block.clone());
        Ok(())
    }

    /// Builds, signs and verifies the next block from `transactions`.
    pub fn build_block(
        &self,
        transactions: Vec<OhmTransaction>,
        timestamp: u64,
        key: &KeyPair,
    ) -> Result<OhmBlock, OhmError> {
        if key.public() != self.maintainer {
            return Err(OhmError::BadMaintainer);
        }
        if transactions.len() > crate::MAX_OHM_BLOCK_TXS {
            return Err(OhmError::TooManyTransactions);
        }
        let mut block = OhmBlock::new_unsigned(
            self.ohm_id,
            self.height + 1,
            self.block_hash,
            timestamp,
            Hash::zero(),
            self.maintainer,
            transactions,
        );
        // Compute the resulting root and commit it to the header before signing.
        let delta = self.apply_transactions(&block.transactions)?;
        block.header.state_root = ohm_state_root(&delta.utxos, &delta.contracts);
        block.header.fee_total = delta.fee_total;
        block.sign(key);
        self.verify_block(&block)?;
        Ok(block)
    }

    /// Builds an OHM transaction spending `inputs` into `outputs` with `fee`, then signs every
    /// input owned by `key`. Inputs are `(prev_out, owner)` pairs.
    pub fn build_transaction(
        &self,
        inputs: Vec<(OutPoint, PublicKey)>,
        outputs: Vec<OhmOutput>,
        fee: Amount,
        key: &KeyPair,
    ) -> OhmTransaction {
        self.build_ovm_transaction(inputs, outputs, fee, None, key)
    }

    /// Builds and signs an OHM transaction with an optional private OVM action.
    ///
    /// The action is attached before signing so that both the signature and the transaction id
    /// commit to it (the transaction id is the OVM deployment id).
    pub fn build_ovm_transaction(
        &self,
        inputs: Vec<(OutPoint, PublicKey)>,
        outputs: Vec<OhmOutput>,
        fee: Amount,
        ovm_action: Option<OvmAction>,
        key: &KeyPair,
    ) -> OhmTransaction {
        let mut tx = OhmTransaction {
            inputs: inputs
                .into_iter()
                .map(|(prev_out, owner)| OhmInput {
                    prev_out,
                    owner,
                    signature: crate::Sig([0u8; 64]),
                })
                .collect(),
            outputs,
            fee,
            ovm_action,
        };
        tx.sign_owned_inputs(key);
        tx
    }

    /// Returns the private contract state for `contract_id`, if this OHM hosts it.
    pub fn contract(&self, contract_id: &Hash) -> Option<&OhmContract> {
        self.contracts.get(contract_id)
    }

    /// Simulates `CallContract` against the current private state without mutating the ledger.
    pub fn simulate_contract_call(
        &self,
        contract_id: &Hash,
        entry_point: &str,
        caller: PublicKey,
        arguments: &[u64],
        gas_limit: u64,
    ) -> Result<OhmCallOutcome, OhmError> {
        if gas_limit < oxydome_ovm::ACTION_INTRINSIC_GAS + oxydome_ovm::CONTRACT_DISPATCH_GAS {
            return Ok(OhmCallOutcome {
                failure: Some(OvmFailureCode::OutOfGas),
                gas_used: gas_limit,
                return_value: None,
                logs: Vec::new(),
            });
        }
        let intrinsic = oxydome_ovm::ACTION_INTRINSIC_GAS + oxydome_ovm::CONTRACT_DISPATCH_GAS;
        let Some(contract) = self.contracts.get(contract_id) else {
            return Ok(OhmCallOutcome {
                failure: Some(OvmFailureCode::ContractNotFound),
                gas_used: oxydome_ovm::ACTION_INTRINSIC_GAS,
                return_value: None,
                logs: Vec::new(),
            });
        };
        let artifact = oxydome_ovm::ContractArtifact::decode(&contract.code)
            .map_err(|error| OhmError::Ovm(error.to_string()))?;
        let Some(function) = artifact.function(entry_point) else {
            return Ok(OhmCallOutcome {
                failure: Some(OvmFailureCode::FunctionNotFound),
                gas_used: intrinsic,
                return_value: None,
                logs: Vec::new(),
            });
        };
        if function.inputs.len() != arguments.len() {
            return Ok(OhmCallOutcome {
                failure: Some(OvmFailureCode::ArgumentCount),
                gas_used: intrinsic,
                return_value: None,
                logs: Vec::new(),
            });
        }
        let mut execution_arguments: Vec<u64> = caller
            .0
            .chunks_exact(8)
            .map(|chunk| u64::from_le_bytes(chunk.try_into().expect("8-byte public-key chunk")))
            .collect();
        execution_arguments.extend(arguments.iter().copied());
        let program = oxydome_ovm::Program::decode(&function.code)
            .map_err(|error| OhmError::Ovm(error.to_string()))?;
        let execution_limit = gas_limit - intrinsic;
        match oxydome_ovm::execute(&program, &execution_arguments, &contract.storage, execution_limit)
        {
            Ok(execution) => Ok(OhmCallOutcome {
                failure: None,
                gas_used: intrinsic + execution.gas_used,
                return_value: execution.return_value,
                logs: execution.logs,
            }),
            Err(failure) => Ok(OhmCallOutcome {
                failure: Some(failure_code(failure.error)),
                gas_used: intrinsic.saturating_add(failure.gas_used).min(gas_limit),
                return_value: None,
                logs: Vec::new(),
            }),
        }
    }

    /// The sum of every unspent OHM output (must equal [`OhmLedger::supply`]).
    pub fn utxo_total(&self) -> Amount {
        self.utxos.values().map(|e| e.output.amount).sum()
    }

    fn check_continuity(&self, block: &OhmBlock) -> Result<(), OhmError> {
        if block.header.ohm_id != self.ohm_id {
            return Err(OhmError::WrongOhm);
        }
        if block.header.height != self.height + 1 {
            return Err(OhmError::BadHeight(block.header.height, self.height));
        }
        if block.header.prev_hash != self.block_hash {
            return Err(OhmError::BadPrevHash);
        }
        if block.header.maintainer != self.maintainer || !block.is_maintainer_signed() {
            return Err(OhmError::BadMaintainer);
        }
        if block.tx_root() != block.header.tx_root {
            return Err(OhmError::BadTxRoot);
        }
        Ok(())
    }

    fn apply_transactions(&self, transactions: &[OhmTransaction]) -> Result<LedgerDelta, OhmError> {
        let mut utxos = self.utxos.clone();
        let mut contracts = self.contracts.clone();
        let mut fee_total: Amount = 0;
        for (index, tx) in transactions.iter().enumerate() {
            tx.validate_structure()
                .map_err(|e| OhmError::BadTransaction(index, e))?;
            let mut input_total: Amount = 0;
            for input in &tx.inputs {
                let key = input.prev_out.key();
                let entry = utxos
                    .get(&key)
                    .cloned()
                    .ok_or(OhmError::MissingInput(input.prev_out))?;
                if entry.output.recipient != input.owner {
                    return Err(OhmError::InputOwnerMismatch(input.prev_out));
                }
                input_total = input_total
                    .checked_add(entry.output.amount)
                    .ok_or(OhmError::Overflow)?;
                utxos.remove(&key);
            }
            let output_total = tx
                .output_total()
                .map_err(|e| OhmError::BadTransaction(index, e))?;
            if input_total != output_total.checked_add(tx.fee).ok_or(OhmError::Overflow)? {
                return Err(OhmError::Conservation);
            }
            let txid = tx.txid();
            if let Some(action) = &tx.ovm_action {
                Self::apply_ovm_action(&mut contracts, action, txid, index, tx)?;
            }
            for (out_index, output) in tx.outputs.iter().enumerate() {
                let outpoint = OutPoint::new(txid, out_index as u32);
                let entry = OhmUtxoEntry::new(outpoint, output.clone(), self.height + 1);
                utxos.insert(entry.key(), entry);
            }
            fee_total = fee_total.checked_add(tx.fee).ok_or(OhmError::Overflow)?;
        }
        let supply = self
            .supply
            .checked_sub(fee_total)
            .ok_or(OhmError::Underflow)?;
        Ok(LedgerDelta {
            utxos,
            contracts,
            supply,
            fee_total,
        })
    }

    /// Executes a private OVM action against the in-progress contract map.
    ///
    /// Mirrors the Ox execution model: a failed call leaves storage untouched (the transaction
    /// still settles), while a deploy of undecodable code invalidates the block.
    fn apply_ovm_action(
        contracts: &mut BTreeMap<Hash, OhmContract>,
        action: &OvmAction,
        txid: Hash,
        tx_index: usize,
        tx: &OhmTransaction,
    ) -> Result<(), OhmError> {
        match action {
            OvmAction::Deploy { code, gas_limit } => {
                oxydome_ovm::Program::decode(code)
                    .map_err(|error| OhmError::Ovm(error.to_string()))?;
                let contract_id = oxydome_ovm::contract_id(txid);
                if contracts.contains_key(&contract_id) {
                    return Err(OhmError::OvmContractCollision);
                }
                if contracts.len() >= oxydome_ovm::MAX_CONTRACTS {
                    return Err(OhmError::OvmContractLimit);
                }
                let required = oxydome_ovm::ACTION_INTRINSIC_GAS
                    .saturating_add(u64::try_from(code.len()).unwrap_or(u64::MAX));
                if required > *gas_limit {
                    return Ok(());
                }
                contracts.insert(
                    contract_id,
                    OhmContract {
                        code: code.clone(),
                        storage: BTreeMap::new(),
                    },
                );
                Ok(())
            }
            OvmAction::DeployContract { artifact, gas_limit } => {
                oxydome_ovm::ContractArtifact::decode(artifact)
                    .map_err(|error| OhmError::Ovm(error.to_string()))?;
                let contract_id = oxydome_ovm::contract_id(txid);
                if contracts.contains_key(&contract_id) {
                    return Err(OhmError::OvmContractCollision);
                }
                if contracts.len() >= oxydome_ovm::MAX_CONTRACTS {
                    return Err(OhmError::OvmContractLimit);
                }
                let required = oxydome_ovm::ACTION_INTRINSIC_GAS
                    .saturating_add(u64::try_from(artifact.len()).unwrap_or(u64::MAX));
                if required > *gas_limit {
                    return Ok(());
                }
                contracts.insert(
                    contract_id,
                    OhmContract {
                        code: artifact.clone(),
                        storage: BTreeMap::new(),
                    },
                );
                Ok(())
            }
            OvmAction::Call {
                contract_id,
                arguments,
                gas_limit,
            } => {
                if *gas_limit < oxydome_ovm::ACTION_INTRINSIC_GAS {
                    return Ok(());
                }
                let Some(contract) = contracts.get(contract_id) else {
                    return Ok(());
                };
                let program = oxydome_ovm::Program::decode(&contract.code)
                    .map_err(|error| OhmError::Ovm(error.to_string()))?;
                Self::execute_contract_call(
                    contracts,
                    contract_id,
                    &program,
                    arguments,
                    *gas_limit,
                    oxydome_ovm::ACTION_INTRINSIC_GAS,
                )
            }
            OvmAction::CallContract {
                contract_id,
                entry_point,
                arguments,
                authority_input,
                gas_limit,
            } => {
                let intrinsic_gas =
                    oxydome_ovm::ACTION_INTRINSIC_GAS + oxydome_ovm::CONTRACT_DISPATCH_GAS;
                if *gas_limit < intrinsic_gas {
                    return Ok(());
                }
                let Some(contract) = contracts.get(contract_id) else {
                    return Ok(());
                };
                let artifact = oxydome_ovm::ContractArtifact::decode(&contract.code)
                    .map_err(|error| OhmError::Ovm(error.to_string()))?;
                let Some(function) = artifact.function(entry_point) else {
                    return Ok(());
                };
                if function.inputs.len() != arguments.len() {
                    return Ok(());
                }
                let Some(authority) = tx.inputs.get(*authority_input as usize) else {
                    return Err(OhmError::BadTransaction(
                        tx_index,
                        "contract authority input index is invalid".into(),
                    ));
                };
                let mut execution_arguments: Vec<u64> = authority
                    .owner
                    .0
                    .chunks_exact(8)
                    .map(|chunk| u64::from_le_bytes(chunk.try_into().expect("8-byte chunk")))
                    .collect();
                execution_arguments.extend(arguments.iter().copied());
                let program = oxydome_ovm::Program::decode(&function.code)
                    .map_err(|error| OhmError::Ovm(error.to_string()))?;
                Self::execute_contract_call(
                    contracts,
                    contract_id,
                    &program,
                    &execution_arguments,
                    *gas_limit,
                    intrinsic_gas,
                )
            }
        }
    }

    fn execute_contract_call(
        contracts: &mut BTreeMap<Hash, OhmContract>,
        contract_id: &Hash,
        program: &oxydome_ovm::Program,
        arguments: &[u64],
        gas_limit: u64,
        intrinsic_gas: u64,
    ) -> Result<(), OhmError> {
        if gas_limit < intrinsic_gas {
            return Ok(());
        }
        let execution_limit = gas_limit - intrinsic_gas;
        let storage = contracts
            .get(contract_id)
            .map(|contract| contract.storage.clone())
            .unwrap_or_default();
        match oxydome_ovm::execute(program, arguments, &storage, execution_limit) {
            Ok(execution) => {
                if let Some(contract) = contracts.get_mut(contract_id) {
                    contract.storage = execution.storage;
                }
                Ok(())
            }
            Err(failure) => match failure.error {
                oxydome_ovm::VmError::InvalidBytecode
                | oxydome_ovm::VmError::ProgramTooLarge
                | oxydome_ovm::VmError::InvalidProgram => {
                    Err(OhmError::Ovm(failure.error.to_string()))
                }
                _ => Ok(()),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ohm_utxo_root, OhmOutput};

    fn key() -> KeyPair {
        KeyPair::from_seed(&[5u8; 32])
    }

    fn ledger(pool: Amount, outputs: usize) -> OhmLedger {
        let owner = key().public();
        let per = pool / outputs as Amount;
        let outs: Vec<OhmOutput> = (0..outputs)
            .map(|_| OhmOutput {
                amount: per,
                recipient: owner,
            })
            .collect();
        OhmLedger::from_genesis(
            ohm_genesis_hash(&Hash::zero()),
            owner,
            &outs,
            Hash::from([9u8; 64]),
        )
    }

    #[test]
    fn genesis_ledger_is_committed() {
        let l = ledger(1000, 1);
        assert_eq!(l.height, 0);
        assert_eq!(l.supply, 1000);
        assert_eq!(l.utxo_total(), 1000);
        assert!(l.contracts.is_empty());
        assert_eq!(l.state_root, ohm_state_root(&l.utxos, &l.contracts));
    }

    #[test]
    fn build_and_apply_block_moves_value() {
        let l = ledger(1000, 1);
        let owner = key().public();
        let genesis_out = l.utxos.values().next().unwrap().outpoint;
        let tx = l.build_transaction(
            vec![(genesis_out, owner)],
            vec![OhmOutput {
                amount: 990,
                recipient: owner,
            }],
            10,
            &key(),
        );
        let block = l.build_block(vec![tx], 42, &key()).unwrap();
        let mut applied = l.clone();
        applied.apply_block(&block).unwrap();
        assert_eq!(applied.height, 1);
        assert_eq!(applied.supply, 990);
        assert_eq!(applied.utxo_total(), 990);
        assert_eq!(applied.block_hash, block.hash());
    }

    #[test]
    fn block_with_wrong_state_root_rejected() {
        let l = ledger(1000, 1);
        let owner = key().public();
        let genesis_out = l.utxos.values().next().unwrap().outpoint;
        let tx = l.build_transaction(
            vec![(genesis_out, owner)],
            vec![OhmOutput {
                amount: 900,
                recipient: owner,
            }],
            100,
            &key(),
        );
        let mut block = l.build_block(vec![tx], 42, &key()).unwrap();
        block.header.state_root = Hash::from([1u8; 64]);
        // Re-sign so the signature is valid and the state-root mismatch is what is detected.
        block.sign(&key());
        assert!(matches!(
            l.verify_block(&block),
            Err(OhmError::BadStateRoot(..))
        ));
    }

    #[test]
    fn double_spend_rejected() {
        let l = ledger(1000, 2);
        let owner = key().public();
        let outs: Vec<OutPoint> = l.utxos.values().map(|e| e.outpoint).collect();
        let tx1 = l.build_transaction(
            vec![(outs[0], owner)],
            vec![OhmOutput {
                amount: 400,
                recipient: owner,
            }],
            100,
            &key(),
        );
        let tx2 = l.build_transaction(
            vec![(outs[0], owner)],
            vec![OhmOutput {
                amount: 400,
                recipient: owner,
            }],
            100,
            &key(),
        );
        let mut block = OhmBlock::new_unsigned(
            l.ohm_id,
            1,
            l.block_hash,
            1,
            Hash::zero(),
            owner,
            vec![tx1, tx2],
        );
        block.sign(&key());
        assert!(matches!(
            l.verify_block(&block),
            Err(OhmError::MissingInput(_))
        ));
    }

    #[test]
    fn non_maintainer_cannot_build() {
        let l = ledger(1000, 1);
        let other = KeyPair::from_seed(&[77u8; 32]);
        assert!(matches!(
            l.build_block(Vec::new(), 1, &other),
            Err(OhmError::BadMaintainer)
        ));
    }

    fn increment_program() -> Vec<u8> {
        oxydome_ovm::Program {
            argument_count: 1,
            local_count: 0,
            instructions: vec![
                oxydome_ovm::Instruction::LoadArg(0),
                oxydome_ovm::Instruction::LoadStorage(0),
                oxydome_ovm::Instruction::Add,
                oxydome_ovm::Instruction::StoreStorage(0),
                oxydome_ovm::Instruction::LoadStorage(0),
                oxydome_ovm::Instruction::Return,
            ],
        }
        .encode()
        .unwrap()
    }

    #[test]
    fn deploys_and_executes_ohm_hosted_contract() {
        let l = ledger(1000, 1);
        let owner = key().public();
        let genesis_out = l.utxos.values().next().unwrap().outpoint;

        let deploy = l.build_ovm_transaction(
            vec![(genesis_out, owner)],
            vec![OhmOutput {
                amount: 900,
                recipient: owner,
            }],
            100,
            Some(OvmAction::Deploy {
                code: increment_program(),
                gas_limit: 1_000,
            }),
            &key(),
        );
        let contract_id = oxydome_ovm::contract_id(deploy.txid());
        let call = l.build_ovm_transaction(
            vec![(OutPoint::new(deploy.txid(), 0), owner)],
            vec![OhmOutput {
                amount: 800,
                recipient: owner,
            }],
            100,
            Some(OvmAction::Call {
                contract_id,
                arguments: vec![5],
                gas_limit: 100,
            }),
            &key(),
        );

        let block = l.build_block(vec![deploy, call], 7, &key()).unwrap();
        let mut applied = l.clone();
        applied.apply_block(&block).unwrap();

        assert_eq!(applied.contracts.len(), 1);
        assert_eq!(applied.contracts[&contract_id].storage.get(&0), Some(&5));
        assert_eq!(applied.height, 1);
        assert_eq!(applied.supply, 800);
        assert_eq!(applied.state_root, block.header.state_root);
        assert_eq!(
            applied.state_root,
            ohm_state_root(&applied.utxos, &applied.contracts)
        );
        // The private contract state changes the anchored root beyond the UTXO set alone.
        assert_ne!(applied.state_root, ohm_utxo_root(&applied.utxos));
    }

    #[test]
    fn undecodable_deployment_invalidates_the_ohm_block() {
        let l = ledger(1000, 1);
        let owner = key().public();
        let genesis_out = l.utxos.values().next().unwrap().outpoint;
        let deploy = l.build_ovm_transaction(
            vec![(genesis_out, owner)],
            vec![OhmOutput {
                amount: 900,
                recipient: owner,
            }],
            100,
            Some(OvmAction::Deploy {
                code: vec![0xff, 0xff, 0xff],
                gas_limit: 1_000,
            }),
            &key(),
        );
        assert!(matches!(
            l.build_block(vec![deploy], 1, &key()),
            Err(OhmError::Ovm(_))
        ));
    }

    #[test]
    fn simulate_contract_call_is_read_only() {
        let l = ledger(1000, 1);
        let owner = key().public();
        let genesis_out = l.utxos.values().next().unwrap().outpoint;
        let code = oxydome_ovm::Program {
            argument_count: (oxydome_ovm::AUTHORITY_WORD_COUNT + 1) as u8,
            local_count: 0,
            instructions: vec![
                oxydome_ovm::Instruction::LoadArg(oxydome_ovm::AUTHORITY_WORD_COUNT as u8),
                oxydome_ovm::Instruction::LoadStorage(0),
                oxydome_ovm::Instruction::Add,
                oxydome_ovm::Instruction::StoreStorage(0),
                oxydome_ovm::Instruction::LoadStorage(0),
                oxydome_ovm::Instruction::Return,
            ],
        }
        .encode()
        .unwrap();
        let artifact = oxydome_ovm::ContractArtifact {
            source_hash: None,
            asset_manifest_hash: None,
            functions: vec![oxydome_ovm::ContractFunction {
                name: "increment".into(),
                inputs: vec![oxydome_ovm::ContractValueType::U64],
                output: Some(oxydome_ovm::ContractValueType::U64),
                code,
            }],
        }
        .encode()
        .unwrap();
        let deploy = l.build_ovm_transaction(
            vec![(genesis_out, owner)],
            vec![OhmOutput {
                amount: 900,
                recipient: owner,
            }],
            100,
            Some(OvmAction::DeployContract {
                artifact,
                gas_limit: 2_000,
            }),
            &key(),
        );
        let contract_id = oxydome_ovm::contract_id(deploy.txid());
        let mut deployed = l.clone();
        let block = deployed.build_block(vec![deploy], 3, &key()).unwrap();
        deployed.apply_block(&block).unwrap();

        let outcome = deployed
            .simulate_contract_call(&contract_id, "increment", owner, &[41], 100)
            .unwrap();
        assert_eq!(outcome.failure, None);
        assert_eq!(outcome.return_value, Some(41));
        // Simulation never mutates the committed ledger.
        assert_eq!(deployed.contracts[&contract_id].storage.get(&0), None);
    }
}
