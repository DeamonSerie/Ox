//! Standalone validation helpers for OHM policies.

use crate::{OhmPolicy, Sig};
use oxydome_crypto::{hash_value, verify};

/// Validates OHM policy bytes and returns the decoded policy.
pub fn validate_policy_bytes(bytes: &[u8]) -> Result<OhmPolicy, String> {
    OhmPolicy::decode(bytes)
}

/// Verifies a signature over the OHM policy by its maintainer.
///
/// Returns `false` for any malformed input; it never panics.
pub fn verify_policy_signature(policy: &OhmPolicy, signature: &Sig) -> bool {
    let policy_hash = hash_value(policy);
    verify(&policy.maintainer, &policy_hash.0, signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{OHM_POLICY_VERSION, PublicKey};
    use oxydome_crypto::KeyPair;

    #[test]
    fn policy_signature_roundtrip() {
        let key = KeyPair::from_seed(&[3u8; 32]);
        let policy = OhmPolicy {
            version: OHM_POLICY_VERSION,
            maintainer: key.public(),
            name: "Acme".to_string(),
            genesis_supply: 1000,
            block_window: 10,
        };
        let policy_hash = hash_value(&policy);
        let sig = key.sign(&policy_hash.0);
        assert!(verify_policy_signature(&policy, &sig));
        assert!(!verify_policy_signature(
            &policy,
            &Sig([0u8; 64])
        ));
        let _ = PublicKey::from([0u8; 32]);
    }
}
