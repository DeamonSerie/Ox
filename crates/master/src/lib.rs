//! Master node: software-integrity admission, epoch governance, header-only block auditing
//! and the periodic deep-audit coordination.
//!
//! Masters do **not** store block bodies or the UTXO set. They store the block header chain
//! (which commits to the state root and window statistics), the admission registry and the
//! governance set, and audit each proposed block through Merkle proofs supplied by the
//! proposer.

pub mod async_audit;
pub mod mvms;
pub mod mvms_config;
pub mod server;
pub mod storage_audit;

pub use mvms::{compute_chain_id, MvmsMaster};
pub use mvms_config::{MvmsBuilder, MvmsConfig, MvmsError, MvmsResult};

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use oxydome_audit::{
    attestation_quorum, audit_root, header_audit, AuditAttestation, AuditError, AuditPackage,
    AuditReport, HeaderAuditContext,
};
use oxydome_consensus::{
    masters_root, AdmissionCertificate, EpochTransition, MasterProposal, VoteKind,
};
use oxydome_core::{
    Amount, Block, BlockHeader, ChainParams, GenesisConfig, GovernanceSet, Hash, PublicKey,
    ValueIndex,
};
use oxydome_crypto::KeyPair;
use oxydome_currency::WindowStats;
use oxydome_net::FinalizedBlockRecord;

/// The admission registry: which software is approved, which nodes are admitted or revoked.
#[derive(Debug, Clone, Default)]
pub struct MasterRegistry {
    /// Approved `CodeManifest` roots.
    pub approved_manifests: BTreeSet<Hash>,
    /// Issued admission certificates by node key.
    pub certificates: BTreeMap<PublicKey, AdmissionCertificate>,
    /// Revoked node keys.
    pub revoked: BTreeSet<PublicKey>,
}

impl MasterRegistry {
    pub fn approve_manifest(&mut self, root: Hash) {
        self.approved_manifests.insert(root);
    }

    pub fn is_manifest_approved(&self, root: &Hash) -> bool {
        self.approved_manifests.contains(root)
    }

    pub fn revoke(&mut self, node: &PublicKey) {
        self.revoked.insert(*node);
    }
}

/// The master's lightweight view of the chain: headers plus accrued window statistics.
#[derive(Debug, Clone)]
pub struct HeaderChain {
    pub headers: Vec<BlockHeader>,
    stats: VecDeque<WindowStats>,
    pub supply: Amount,
    pub value_index: ValueIndex,
    pub generation: u64,
    pub epoch: u64,
    pub genesis_supply: Amount,
    pub epoch_minted: Amount,
    pub epoch_burned: Amount,
    pub epoch_withdrawn: Amount,
    /// Previous block's total server reward for master reward derivative audit.
    pub prev_server_block_reward: Option<Amount>,
    /// On-chain Ox price oracle.
    pub ox_price: Amount,
    /// Last height at which the GAS price was updated.
    pub price_last_update_height: u64,
}

impl HeaderChain {
    pub fn from_genesis(genesis: &Block, params: &ChainParams) -> Self {
        Self {
            headers: vec![genesis.header.clone()],
            stats: VecDeque::new(),
            supply: genesis.header.supply,
            value_index: genesis.header.value_index,
            generation: genesis.header.generation,
            epoch: genesis.header.epoch,
            genesis_supply: params.genesis_supply,
            epoch_minted: 0,
            epoch_burned: 0,
            epoch_withdrawn: 0,
            prev_server_block_reward: None,
            ox_price: params.ox_price_reference,
            price_last_update_height: 0,
        }
    }

    pub fn head(&self) -> &BlockHeader {
        self.headers.last().expect("chain always has genesis")
    }

    pub fn prev_utxo_root(&self) -> Hash {
        self.head().utxo_root
    }

    /// Sum of the last `block_window - 1` blocks' statistics (the current block is added by
    /// the audit function).
    pub fn previous_window(&self, params: &ChainParams) -> WindowStats {
        let take = params.block_window.saturating_sub(1).max(1) as usize;
        let mut acc = WindowStats::default();
        for s in self.stats.iter().rev().take(take) {
            acc.volume = acc.volume.saturating_add(s.volume);
            acc.tx_count = acc.tx_count.saturating_add(s.tx_count);
            acc.exit_amount = acc.exit_amount.saturating_add(s.exit_amount);
        }
        acc
    }

    /// Records a finalized block header.
    pub fn append(&mut self, block: &Block, params: &ChainParams) -> Result<(), String> {
        // An epoch change is effectuated by a governance-co-signed `EpochTransition`, never by
        // a self-declared header field. Rejecting it here (and in `MasterNode::audit`) stops a
        // proposer from resetting the per-epoch mint/burn/withdraw caps by bumping the header.
        if block.header.epoch != self.epoch {
            return Err(format!(
                "unsolicited epoch change from {} to {}",
                self.epoch, block.header.epoch
            ));
        }
        self.stats.push_back(WindowStats {
            volume: block.header.volume,
            tx_count: block.header.tx_count,
            exit_amount: block.header.exit_amount,
            highest_tx_value: 0,
            express_flow: 0,
        });
        let w = params.block_window.max(1) as usize;
        while self.stats.len() > w {
            self.stats.pop_front();
        }
        // Accrue governance counters from the operations carried in the block.
        for op in &block.operations {
            match op {
                oxydome_core::Operation::Mint(m) => {
                    self.epoch_minted = self.epoch_minted.saturating_add(m.amount)
                }
                oxydome_core::Operation::Burn(b) => {
                    self.epoch_burned = self.epoch_burned.saturating_add(b.amount)
                }
                oxydome_core::Operation::Withdraw(w) => {
                    self.epoch_withdrawn = self.epoch_withdrawn.saturating_add(w.amount)
                }
                oxydome_core::Operation::BlockRewards(r) => {
                    // Derive the next block's master-reward baseline from this block's server
                    // rewards (the producing node does the same in `produce_block`). Without
                    // tracking it, `header_audit` would derive a different master-reward total
                    // than the proposer and reject every reward-bearing block.
                    self.prev_server_block_reward = Some(r.server_total());
                }
                oxydome_core::Operation::Gas(g) => {
                    if let oxydome_core::GasAction::SetOxPrice { price } = &g.action {
                        self.ox_price = *price;
                        self.price_last_update_height = block.header.height;
                    }
                }
                oxydome_core::Operation::Rewards(_)
                | oxydome_core::Operation::Dao(_)
                | oxydome_core::Operation::Ohm(_)
                | oxydome_core::Operation::PriceChange(_) => {}
                oxydome_core::Operation::StorageLabel(_) => {}
                oxydome_core::Operation::StorageAudit(_) => {}
                oxydome_core::Operation::Timer(_) => {}
                oxydome_core::Operation::FileStore(_) => {}
                oxydome_core::Operation::FileAccess(_) => {}
                oxydome_core::Operation::FileDelete(_) => {}
                oxydome_core::Operation::LiquidityPool(_) => {}
                oxydome_core::Operation::Speedometer(_) => {}
                oxydome_core::Operation::NodeLeave(_) => {}
                oxydome_core::Operation::DepartureEarnings(_) => {}
                oxydome_core::Operation::ExpressBusDeposit(_) => {}
                oxydome_core::Operation::ExpressBusWithdraw(_) => {}
            }
        }
        self.supply = block.header.supply;
        self.value_index = block.header.value_index;
        self.generation = block.header.generation;
        self.headers.push(block.header.clone());
        Ok(())
    }
}

/// A running master node.
#[derive(Debug, Clone)]
pub struct MasterNode {
    pub key: KeyPair,
    pub gov: GovernanceSet,
    pub params: ChainParams,
    pub epoch: u64,
    pub registry: MasterRegistry,
    pub chain: HeaderChain,
}

impl MasterNode {
    /// Creates a master from genesis configuration. The genesis block must be the one built by
    /// [`oxydome_state::ChainState::genesis`] from the same config.
    pub fn new(key: KeyPair, gov: GovernanceSet, params: ChainParams, genesis: &Block) -> Self {
        Self {
            key,
            gov,
            params: params.clone(),
            epoch: genesis.header.epoch,
            registry: MasterRegistry::default(),
            chain: HeaderChain::from_genesis(genesis, &params),
        }
    }

    pub fn public(&self) -> PublicKey {
        self.key.public()
    }

    pub fn masters_root(&self) -> Hash {
        masters_root(&self.gov.masters)
    }

    /// Handles an admission request. Returns a certificate when the manifest is approved and
    /// the node is not revoked.
    pub fn handle_admission(
        &mut self,
        node: PublicKey,
        manifest_root: Hash,
        now: u64,
    ) -> Result<AdmissionCertificate, String> {
        if self.registry.revoked.contains(&node) {
            return Err("node is revoked".into());
        }
        if !self.registry.is_manifest_approved(&manifest_root) {
            return Err("software manifest is not approved".into());
        }
        let cert = AdmissionCertificate::issue(
            &self.key,
            node,
            manifest_root,
            self.epoch,
            now,
            now + 86_400,
        );
        self.registry.certificates.insert(node, cert.clone());
        Ok(cert)
    }

    /// Audits a proposed block and returns the master's signed attestation.
    pub fn audit(&self, package: &AuditPackage) -> Result<AuditAttestation, AuditError> {
        // Epoch changes are governance-co-signed transitions, not self-declared header fields.
        if package.block.header.epoch != self.chain.epoch {
            return Err(AuditError::Guardrail(format!(
                "unsolicited epoch change from {} to {}",
                self.chain.epoch, package.block.header.epoch
            )));
        }
        let ctx = HeaderAuditContext {
            pre_utxo_root: self.chain.prev_utxo_root(),
            prev_supply: self.chain.supply,
            prev_value_index: self.chain.value_index,
            prev_generation: self.chain.generation,
            previous_window: self.chain.previous_window(&self.params),
            genesis_supply: self.chain.genesis_supply,
            epoch_minted: self.chain.epoch_minted,
            epoch_burned: self.chain.epoch_burned,
            epoch_withdrawn: self.chain.epoch_withdrawn,
            prev_server_block_reward: self.chain.prev_server_block_reward,
            ox_price: self.chain.ox_price,
            price_last_update_height: self.chain.price_last_update_height,
            gov: &self.gov,
            params: &self.params,
        };
        let report: AuditReport = header_audit(&ctx, package)?;
        Ok(AuditAttestation::sign(&report, &self.key))
    }

    /// Records a finalized block header after verifying its finality evidence.
    ///
    /// Masters validate the signatures and header chain but do not independently execute OVM.
    pub fn on_finalized(&mut self, finalized: &FinalizedBlockRecord) -> Result<(), String> {
        let block = &finalized.block;
        let evidence = &finalized.evidence;
        if block.header.height != self.chain.head().height.saturating_add(1)
            || block.header.prev_hash != oxydome_crypto::hash_value(self.chain.head())
            || !block.roots_match()
        {
            return Err("finalized header does not extend the current master tip".into());
        }
        let prepare = &evidence.prepare_qc;
        let commit = &evidence.commit_qc;
        if prepare.height != block.header.height
            || prepare.block_hash != block.hash()
            || prepare.kind != VoteKind::Prepare
            || !prepare.has_quorum(&self.gov, &self.params)
            || commit.height != block.header.height
            || commit.block_hash != block.hash()
            || commit.kind != VoteKind::Commit
            || commit.view != prepare.view
            || !commit.has_quorum(&self.gov, &self.params)
        {
            return Err("finalized block lacks valid prepare/commit quorum certificates".into());
        }
        if !attestation_quorum(block, &evidence.attestations, &self.gov, &self.params) {
            return Err("finalized block lacks a valid master attestation quorum".into());
        }
        if !oxydome_consensus::votes::master_check_quorum(
            &evidence.master_checks,
            block.header.epoch,
            self.masters_root(),
            &self.gov,
            &self.params,
        ) {
            return Err("finalized block lacks a valid master-check quorum".into());
        }
        self.chain.append(block, &self.params)?;
        Ok(())
    }

    /// Co-signs an epoch transition to change the master set.
    pub fn sign_transition(&self, transition: &mut EpochTransition) {
        transition.add_master_signature(&self.key);
    }

    /// Applies an epoch transition if it is validly co-signed.
    pub fn apply_transition(&mut self, transition: &EpochTransition) -> Result<(), String> {
        if !transition.is_valid(&self.gov, &self.params) {
            return Err("epoch transition lacks master super-majority".into());
        }
        self.gov.masters = transition.masters.clone();
        self.epoch = transition.epoch;
        Ok(())
    }

    /// Returns the admission registry's approved manifests.
    pub fn approved_manifests(&self) -> Vec<Hash> {
        self.registry.approved_manifests.iter().copied().collect()
    }

    /// Verifies a node's certificate against the current policy.
    pub fn verify_certificate(&self, cert: &AdmissionCertificate, now: u64) -> bool {
        let approved: Vec<Hash> = self.approved_manifests();
        cert.is_valid(&self.gov, &approved, now) && !self.registry.revoked.contains(&cert.node)
    }

    /// The audit root for logging/comparison.
    pub fn audit_root_of(package: &AuditPackage) -> Hash {
        audit_root(package)
    }
}

/// Builds a genesis-derived master set from a config.
pub fn genesis_master(key: KeyPair, config: &GenesisConfig, genesis: &Block) -> MasterNode {
    let gov = GovernanceSet::new(config.masters.clone(), config.nodes.clone());
    MasterNode::new(key, gov, config.params.clone(), genesis)
}

/// Convenience alias for [`MasterProposal`] re-export.
pub type Proposal = MasterProposal;

#[cfg(test)]
mod tests {
    use super::*;
    use oxydome_core::{GenesisAllocation, GenesisConfig, TxOutput};
    use oxydome_state::ChainState;

    fn reward_config() -> (
        MasterNode,
        ChainState,
        GovernanceSet,
        ChainParams,
        KeyPair,
        KeyPair,
    ) {
        let master_key = KeyPair::from_seed(&[1u8; 32]);
        let node_key = KeyPair::from_seed(&[2u8; 32]);
        let filler_key = KeyPair::from_seed(&[3u8; 32]);
        let mut params = ChainParams::default_local();
        params.block_window = 10;
        params.block_rewards_enabled = true;
        let config = GenesisConfig {
            params: params.clone(),
            allocations: vec![
                GenesisAllocation {
                    recipient: node_key.public(),
                    amount: 10_000,
                },
                GenesisAllocation {
                    recipient: master_key.public(),
                    amount: 10_000,
                },
                GenesisAllocation {
                    recipient: filler_key.public(),
                    amount: 999_980_000,
                },
            ],
            masters: vec![master_key.public()],
            nodes: vec![node_key.public()],
            timestamp: 0,
        };
        let (state, genesis, gov) = ChainState::genesis(&config).unwrap();
        let master = MasterNode::new(master_key.clone(), gov.clone(), params.clone(), &genesis);
        (master, state, gov, params, master_key, node_key)
    }

    #[test]
    fn master_tracks_previous_server_reward_from_block_rewards() {
        let (mut master, state, gov, params, _master_key, node_key) = reward_config();

        let reward = oxydome_core::Operation::BlockRewards(oxydome_core::BlockRewardDistribution {
            server_outputs: vec![TxOutput::locked_reward(42, node_key.public())],
            master_outputs: Vec::new(),
        });
        let block = state
            .build_block(
                &gov,
                &params,
                Vec::new(),
                vec![reward],
                node_key.public(),
                1,
            )
            .unwrap();
        master.chain.append(&block, &params).unwrap();
        assert_eq!(master.chain.prev_server_block_reward, Some(42));

        // The baseline rolls forward to the next reward-bearing block so `header_audit` can
        // derive the same master-reward total as the proposer.
        let state1 = state.apply_block(&block, &gov, &params).unwrap();
        let reward2 =
            oxydome_core::Operation::BlockRewards(oxydome_core::BlockRewardDistribution {
                server_outputs: vec![TxOutput::locked_reward(88, node_key.public())],
                master_outputs: Vec::new(),
            });
        let block2 = state1
            .build_block(
                &gov,
                &params,
                Vec::new(),
                vec![reward2],
                node_key.public(),
                2,
            )
            .unwrap();
        master.chain.append(&block2, &params).unwrap();
        assert_eq!(master.chain.prev_server_block_reward, Some(88));
    }

    #[test]
    fn master_rejects_a_self_declared_epoch_change() {
        let (mut master, state, gov, params, _master_key, node_key) = reward_config();
        let mut block = state
            .build_block(&gov, &params, Vec::new(), Vec::new(), node_key.public(), 1)
            .unwrap();
        block.header.epoch = block.header.epoch + 1;
        assert!(master.chain.append(&block, &params).is_err());
        assert_eq!(master.chain.epoch_minted, 0);
    }
}
