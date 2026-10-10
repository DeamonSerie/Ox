//! Wallet-facing index: transaction locations and per-address history.
//!
//! The index is derived entirely from already-committed on-chain state, so it is always
//! rebuildable from the block list; the optional [`IndexStore`] persists a bincode snapshot
//! (alongside the sign-of-life ledger store) so a fresh restart need not rescan every block.

use oxydome_core::{Amount, Block, Hash, PublicKey};
use oxydome_net::{HistoryEntry, TxLocation};
use oxydome_state::UtxoLedger;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Where wallet activity has occurred in the chain.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletIndex {
    /// txid -> confirmation location for every applied (on-chain) transaction.
    pub by_txid: BTreeMap<Hash, TxLocation>,
    /// owner -> sorted (height, position) -> history entry.
    pub by_addr: BTreeMap<PublicKey, BTreeMap<(u64, u32), HistoryEntry>>,
}

impl WalletIndex {
    /// An empty index covering no blocks.
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends the effects of a block, using the ledger *before* the block for input amounts.
    ///
    /// For each transaction the wallet history records, per owner: `in_amount` = the value of
    /// the owner's outputs in this transaction (what the wallet received) and `out_amount` =
    /// the value of the owner's inputs (what the wallet paid), including fees charged against
    /// spent outputs.
    pub fn record_block(&mut self, block: &Block, pre_utxo: &UtxoLedger) {
        let block_hash = block.hash();
        let height = block.header.height;
        for (position, tx) in block.transactions.iter().enumerate() {
            let location = TxLocation {
                height,
                block_hash,
                position: position as u32,
            };
            self.by_txid.insert(tx.txid(), location);

            let mut flows: BTreeMap<PublicKey, (Amount, Amount)> = BTreeMap::new();
            for input in &tx.inputs {
                if let Some(entry) = pre_utxo.get(&input.prev_out) {
                    let flow = flows.entry(entry.output.recipient).or_default();
                    flow.0 = flow.0.saturating_add(entry.output.amount);
                }
            }
            for output in &tx.outputs {
                let flow = flows.entry(output.recipient).or_default();
                flow.1 = flow.1.saturating_add(output.amount);
            }
            if let Some(action) = &tx.ovm_action {
                if let (Some(input), Some(receipt)) = (
                    tx.inputs.first(),
                    block
                        .ovm_receipts
                        .iter()
                        .find(|receipt| receipt.txid == tx.txid()),
                ) {
                    let refund = action.gas_limit().saturating_sub(receipt.gas_used);
                    if refund > 0 {
                        let flow = flows.entry(input.owner).or_default();
                        flow.1 = flow.1.saturating_add(u128::from(refund));
                    }
                }
            }
            for (owner, (out_amount, in_amount)) in flows {
                let entry = HistoryEntry {
                    txid: tx.txid(),
                    height,
                    block_hash,
                    position: position as u32,
                    in_amount,
                    out_amount,
                };
                self.by_addr
                    .entry(owner)
                    .or_default()
                    .insert((height, position as u32), entry);
            }
        }
    }
}

/// Durable snapshot storage for a [`WalletIndex`], stored in its own sled tree.
#[derive(Debug)]
pub struct IndexStore {
    db: sled::Db,
}

impl IndexStore {
    /// Opens (or creates) the index store rooted at `path`.
    pub fn open(path: &std::path::Path) -> Result<Self, crate::NodeError> {
        let db = sled::open(path).map_err(|e| crate::NodeError::Ledger(e.to_string()))?;
        Ok(Self { db })
    }

    /// Persists the current index snapshot.
    pub fn save(&self, index: &WalletIndex) -> Result<(), crate::NodeError> {
        let bytes =
            bincode::serialize(index).map_err(|e| crate::NodeError::Ledger(e.to_string()))?;
        self.db
            .insert(b"index", bytes)
            .map_err(|e| crate::NodeError::Ledger(e.to_string()))?;
        self.db
            .flush()
            .map_err(|e| crate::NodeError::Ledger(e.to_string()))?;
        Ok(())
    }

    /// Loads the persisted snapshot, if any.
    pub fn load(&self) -> Result<Option<WalletIndex>, crate::NodeError> {
        match self
            .db
            .get(b"index")
            .map_err(|e| crate::NodeError::Ledger(e.to_string()))?
        {
            Some(raw) => bincode::deserialize(&raw)
                .map(Some)
                .map_err(|e| crate::NodeError::Ledger(e.to_string())),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxydome_core::{OutPoint, OvmAction, OvmReceipt, Transaction, TxOutput, ValueIndex};
    use oxydome_crypto::{Hash, KeyPair};
    use oxydome_state::{UtxoEntry, UtxoLedger};

    #[test]
    fn records_flows_per_owner() {
        let alice_key = KeyPair::from_seed(&[1u8; 32]);
        let alice = alice_key.public();
        let bob = KeyPair::from_seed(&[2u8; 32]).public();

        let fund_outpoint = OutPoint::new(Hash::zero(), 0);
        let pre_utxo = UtxoLedger::new().insert(UtxoEntry::new(
            fund_outpoint,
            TxOutput::spendable(100, alice),
            0,
        ));

        let mut tx = Transaction::new_unsigned(
            vec![(fund_outpoint, alice)],
            vec![TxOutput::spendable(95, bob)],
            5,
        );
        tx.sign_input(0, &alice_key);

        let block = Block::build_header(
            1,
            oxydome_core::OVM_EXECUTION_VERSION,
            1,
            u64::MAX,
            Hash::zero(),
            pre_utxo.root(),
            0,
            0,
            0,
            ValueIndex::from_raw(1_000_000_000_000),
            alice,
            1,
            vec![tx],
            vec![],
        );

        let mut index = WalletIndex::new();
        index.record_block(&block, &pre_utxo);

        let txid = block.transactions[0].txid();
        assert_eq!(index.by_txid.len(), 1);
        assert_eq!(
            index.by_txid.get(&txid).cloned(),
            Some(TxLocation {
                height: 1,
                block_hash: block.hash(),
                position: 0,
            })
        );

        let alice_entry = &index.by_addr[&alice][&(1, 0)];
        assert_eq!(alice_entry.in_amount, 0);
        assert_eq!(alice_entry.out_amount, 100);

        let bob_entry = &index.by_addr[&bob][&(1, 0)];
        assert_eq!(bob_entry.in_amount, 95);
        assert_eq!(bob_entry.out_amount, 0);
    }

    #[test]
    fn records_ovm_gas_refund_as_a_received_output() {
        let alice_key = KeyPair::from_seed(&[1u8; 32]);
        let alice = alice_key.public();
        let bob = KeyPair::from_seed(&[2u8; 32]).public();
        let outpoint = OutPoint::new(Hash::zero(), 0);
        let pre_utxo =
            UtxoLedger::new().insert(UtxoEntry::new(outpoint, TxOutput::spendable(100, alice), 0));
        let mut tx = Transaction::new_unsigned(
            vec![(outpoint, alice)],
            vec![TxOutput::spendable(94, bob)],
            6,
        );
        tx.ovm_action = Some(OvmAction::Call {
            contract_id: Hash::zero(),
            arguments: Vec::new(),
            gas_limit: 5,
        });
        tx.sign_input(0, &alice_key);
        let mut block = Block::build_header(
            1,
            oxydome_core::OVM_EXECUTION_VERSION,
            1,
            u64::MAX,
            Hash::zero(),
            pre_utxo.root(),
            0,
            0,
            0,
            ValueIndex::from_raw(1_000_000_000_000),
            alice,
            1,
            vec![tx.clone()],
            vec![],
        );
        block.ovm_receipts = vec![OvmReceipt {
            txid: tx.txid(),
            gas_used: 3,
            failure: None,
            return_data: Vec::new(),
            logs: Vec::new(),
        }];

        let mut index = WalletIndex::new();
        index.record_block(&block, &pre_utxo);
        assert_eq!(index.by_addr[&alice][&(1, 0)].in_amount, 2);
        assert_eq!(index.by_addr[&bob][&(1, 0)].in_amount, 94);
    }
}
