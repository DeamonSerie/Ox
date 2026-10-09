//! Admission certificates.
//!
//! A server node may only join the network if a master node has verified that the node's
//! software (`CodeManifest` root) is in the approved set. The master signs an
//! [`AdmissionCertificate`] binding the node's public key to that manifest root and an epoch.

use oxydome_core::{GovernanceSet, PublicKey, Sig};
use oxydome_crypto::{encode, verify, Hash, KeyPair};
use serde::{Deserialize, Serialize};

/// The data a master commits to when admitting a node.
#[derive(Serialize)]
struct AdmissionData {
    node: PublicKey,
    manifest_root: Hash,
    epoch: u64,
    issued_at: u64,
    expiry: u64,
}

/// A master-signed statement that `node` runs approved software until `expiry`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionCertificate {
    pub node: PublicKey,
    pub manifest_root: Hash,
    pub epoch: u64,
    pub issued_at: u64,
    pub expiry: u64,
    pub master: PublicKey,
    pub signature: Sig,
}

impl AdmissionCertificate {
    fn data(&self) -> AdmissionData {
        AdmissionData {
            node: self.node,
            manifest_root: self.manifest_root,
            epoch: self.epoch,
            issued_at: self.issued_at,
            expiry: self.expiry,
        }
    }

    /// Issues a certificate as a master node.
    pub fn issue(
        master_key: &KeyPair,
        node: PublicKey,
        manifest_root: Hash,
        epoch: u64,
        issued_at: u64,
        expiry: u64,
    ) -> Self {
        let mut cert = Self {
            node,
            manifest_root,
            epoch,
            issued_at,
            expiry,
            master: master_key.public(),
            signature: Sig([0u8; 64]),
        };
        cert.signature = master_key.sign(&encode(&cert.data()));
        cert
    }

    /// Verifies the master signature.
    pub fn signature_valid(&self) -> bool {
        verify(&self.master, &encode(&self.data()), &self.signature)
    }

    /// Full validity: correct signature, master is a member, manifest approved, not expired.
    pub fn is_valid(&self, gov: &GovernanceSet, approved_manifests: &[Hash], now: u64) -> bool {
        self.signature_valid()
            && gov.contains_master(&self.master)
            && approved_manifests.contains(&self.manifest_root)
            && now <= self.expiry
    }
}
