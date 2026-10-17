//! Merkle proof verification utilities for cross-chain verification.
//!
//! This module extends the existing Merkle tree functionality to support
//! cross-chain verification requirements including maximum path depth validation
//! and proof serialization/deserialization.

use crate::{Hash, MerkleProof};
use thiserror::Error;

/// Maximum allowed Merkle proof depth (64 levels as per requirements).
pub const MAX_MERKLE_DEPTH: usize = 64;

/// Error type for Merkle proof operations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MerkleError {
    #[error("merkle proof depth {0} exceeds maximum {1}")]
    DepthExceeded(usize, usize),
    #[error("merkle proof verification failed")]
    VerificationFailed,
    #[error("merkle proof is empty")]
    EmptyProof,
    #[error("invalid leaf hash")]
    InvalidLeaf,
    #[error("invalid root hash")]
    InvalidRoot,
    #[error("proof serialization failed: {0}")]
    SerializationError(String),
    #[error("proof deserialization failed: {0}")]
    DeserializationError(String),
}

/// Result type for Merkle operations.
pub type MerkleResult<T> = Result<T, MerkleError>;

/// Verifies a Merkle inclusion proof with depth validation.
///
/// This function extends the basic Merkle verification to include:
/// - Maximum depth validation (64 levels as per requirements)
/// - Proper error reporting
/// - Input validation
///
/// # Arguments
/// * `root` - The Merkle root to verify against
/// * `leaf` - The leaf hash being proven
/// * `proof` - The Merkle inclusion proof
/// * `max_depth` - Maximum allowed proof depth (default: 64)
///
/// # Returns
/// * `Ok(true)` if the proof is valid and within depth limits
/// * `Ok(false)` if the proof verification fails
/// * `Err(MerkleError)` if the proof depth exceeds limits or inputs are invalid
pub fn verify_merkle_proof(
    root: &Hash,
    leaf: &Hash,
    proof: &MerkleProof,
    max_depth: Option<usize>,
) -> MerkleResult<bool> {
    let max_depth = max_depth.unwrap_or(MAX_MERKLE_DEPTH);

    // Validate proof depth
    if proof.siblings.len() > max_depth {
        return Err(MerkleError::DepthExceeded(proof.siblings.len(), max_depth));
    }

    // Perform verification using existing crypto crate function
    let valid = crate::merkle_verify(root, leaf, proof);

    if valid {
        Ok(true)
    } else {
        Err(MerkleError::VerificationFailed)
    }
}

/// Builds and serializes a Merkle proof for a leaf at the given index.
///
/// # Arguments
/// * `leaves` - The list of leaf hashes
/// * `index` - The index of the leaf to build proof for
/// * `max_depth` - Maximum allowed proof depth (default: 64)
///
/// # Returns
/// * `Ok(proof)` - The Merkle proof if index is valid
/// * `Err(MerkleError)` - If index is out of range or depth exceeds limits
pub fn build_merkle_proof_with_limit(
    leaves: &[Hash],
    index: usize,
    max_depth: Option<usize>,
) -> MerkleResult<MerkleProof> {
    let max_depth = max_depth.unwrap_or(MAX_MERKLE_DEPTH);

    // Build proof using existing crypto crate function
    let proof = crate::merkle_proof(leaves, index);

    // Validate depth
    if proof.siblings.len() > max_depth {
        return Err(MerkleError::DepthExceeded(proof.siblings.len(), max_depth));
    }

    Ok(proof)
}

/// Serializes a Merkle proof to bytes.
///
/// Uses bincode for efficient serialization.
pub fn serialize_merkle_proof(proof: &MerkleProof) -> MerkleResult<Vec<u8>> {
    bincode::serialize(proof).map_err(|e| MerkleError::SerializationError(e.to_string()))
}

/// Deserializes a Merkle proof from bytes.
///
/// Uses bincode for efficient deserialization.
pub fn deserialize_merkle_proof(bytes: &[u8]) -> MerkleResult<MerkleProof> {
    bincode::deserialize(bytes).map_err(|e| MerkleError::DeserializationError(e.to_string()))
}

/// Computes the Merkle root from leaves with depth validation.
///
/// # Arguments
/// * `leaves` - The list of leaf hashes
/// * `max_depth` - Maximum allowed proof depth (default: 64)
///
/// # Returns
/// * `Ok(root)` - The computed Merkle root
/// * `Err(MerkleError)` - If the depth would exceed limits (shouldn't happen normally)
pub fn compute_merkle_root_with_limit(
    leaves: &[Hash],
    max_depth: Option<usize>,
) -> MerkleResult<Hash> {
    let max_depth = max_depth.unwrap_or(MAX_MERKLE_DEPTH);

    // For a complete binary tree, depth = ceil(log2(leaves + 1))
    // For 2^64 leaves, we'd need 64 levels, so this is a theoretical check
    let depth = if leaves.is_empty() {
        0
    } else {
        (leaves.len() as f64).log2().ceil() as usize
    };

    if depth > max_depth {
        return Err(MerkleError::DepthExceeded(depth, max_depth));
    }

    Ok(crate::merkle_root(leaves))
}

/// Verifies a Merkle proof with detailed error information.
///
/// This function provides more detailed error information than verify_merkle_proof,
/// including the expected and actual root hashes when verification fails.
pub fn verify_merkle_proof_detailed(
    root: &Hash,
    leaf: &Hash,
    proof: &MerkleProof,
    max_depth: Option<usize>,
) -> Result<(), MerkleProofVerificationError> {
    let max_depth = max_depth.unwrap_or(MAX_MERKLE_DEPTH);

    // Validate proof depth
    if proof.siblings.len() > max_depth {
        return Err(MerkleProofVerificationError::depth_exceeded(
            proof.siblings.len(),
            max_depth,
        ));
    }

    // Perform verification
    let mut acc = crate::merkle_leaf_hash(leaf);
    let mut idx = proof.index;

    for sibling in &proof.siblings {
        acc = if idx % 2 == 0 {
            crate::merkle_node_hash(&acc, sibling)
        } else {
            crate::merkle_node_hash(sibling, &acc)
        };
        idx /= 2;
    }

    if &acc == root {
        Ok(())
    } else {
        Err(MerkleProofVerificationError::root_mismatch(
            root.clone(),
            acc,
        ))
    }
}

/// Detailed error information for Merkle proof verification failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProofVerificationError {
    kind: MerkleProofVerificationErrorKind,
}

impl MerkleProofVerificationError {
    pub fn depth_exceeded(actual: usize, max: usize) -> Self {
        Self {
            kind: MerkleProofVerificationErrorKind::DepthExceeded(actual, max),
        }
    }

    pub fn root_mismatch(expected: Hash, actual: Hash) -> Self {
        Self {
            kind: MerkleProofVerificationErrorKind::RootMismatch { expected, actual },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MerkleProofVerificationErrorKind {
    DepthExceeded(usize, usize),
    RootMismatch { expected: Hash, actual: Hash },
}

impl std::fmt::Display for MerkleProofVerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            MerkleProofVerificationErrorKind::DepthExceeded(actual, max) => {
                write!(f, "merkle proof depth {actual} exceeds maximum {max}")
            }
            MerkleProofVerificationErrorKind::RootMismatch { expected, actual } => {
                write!(
                    f,
                    "merkle root mismatch: expected {}, actual {}",
                    expected.to_hex(),
                    actual.to_hex()
                )
            }
        }
    }
}

impl std::error::Error for MerkleProofVerificationError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_merkle_proof_valid() {
        let leaves: Vec<Hash> = (0u64..7).map(|i| crate::hash(&i.to_le_bytes())).collect();
        let root = crate::merkle_root(&leaves);
        let leaf = &leaves[3];
        let proof = crate::merkle_proof(&leaves, 3);

        let result = verify_merkle_proof(&root, leaf, &proof, None);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn verify_merkle_proof_exceeds_depth() {
        let leaves: Vec<Hash> = (0u64..7).map(|i| crate::hash(&i.to_le_bytes())).collect();
        let root = crate::merkle_root(&leaves);
        let leaf = &leaves[3];

        // Create a proof with too many siblings
        let mut siblings = vec![Hash::zero(); MAX_MERKLE_DEPTH + 1];
        let proof = MerkleProof { siblings, index: 3 };

        let result = verify_merkle_proof(&root, leaf, &proof, None);
        assert!(matches!(result, Err(MerkleError::DepthExceeded(_, _))));
    }

    #[test]
    fn test_merkle_proof_serialization() {
        let leaves: Vec<Hash> = (0u64..7).map(|i| crate::hash(&i.to_le_bytes())).collect();
        let proof = crate::merkle_proof(&leaves, 3);

        // Serialize
        let bytes = serialize_merkle_proof(&proof).unwrap();

        // Deserialize
        let deserialized = deserialize_merkle_proof(&bytes).unwrap();

        assert_eq!(proof, deserialized);
    }

    #[test]
    fn test_build_merkle_proof_with_limit() {
        let leaves: Vec<Hash> = (0u64..7).map(|i| crate::hash(&i.to_le_bytes())).collect();

        // Should succeed
        let proof = build_merkle_proof_with_limit(&leaves, 3, None).unwrap();
        assert_eq!(proof.index, 3);
        assert!(proof.siblings.len() <= MAX_MERKLE_DEPTH);
    }

    #[test]
    fn test_compute_merkle_root_with_limit() {
        let leaves: Vec<Hash> = (0u64..7).map(|i| crate::hash(&i.to_le_bytes())).collect();

        let root = compute_merkle_root_with_limit(&leaves, None).unwrap();
        let expected = crate::merkle_root(&leaves);

        assert_eq!(root, expected);
    }

    #[test]
    fn verify_merkle_proof_detailed_root_mismatch() {
        let leaves: Vec<Hash> = (0u64..7).map(|i| crate::hash(&i.to_le_bytes())).collect();
        let root = crate::merkle_root(&leaves);
        let leaf = &leaves[3];
        let proof = crate::merkle_proof(&leaves, 3);

        // Use wrong root
        let wrong_root = Hash::zero();

        let result = verify_merkle_proof_detailed(&wrong_root, leaf, &proof, None);
        assert!(matches!(
            result,
            Err(MerkleProofVerificationError {
                kind: MerkleProofVerificationErrorKind::RootMismatch { .. }
            })
        ));
    }

    #[test]
    fn verify_merkle_proof_empty_leaves() {
        let leaves: Vec<Hash> = vec![];
        let root = crate::merkle_root(&leaves);

        // Empty leaves should have zero root
        assert_eq!(root, Hash::zero());
    }
}
