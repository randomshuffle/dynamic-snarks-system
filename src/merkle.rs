//! Canonical Poseidon2 Merkle vector commitments and reusable multiproofs.

use std::collections::{BTreeMap, BTreeSet};

use p3_bn254::Bn254;
use p3_field::PrimeCharacteristicRing;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::hash::{Digest, hash_leaf, hash_node};

/// A deterministic vector commitment.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Commitment {
    /// Poseidon2 Merkle root.
    pub root: Digest,
    /// Logical (unpadded) vector length.
    pub len: usize,
}

/// One canonical authentication node in a Merkle multiproof.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProofNode {
    /// Level zero is the leaf layer.
    pub level: usize,
    /// Node offset within the level.
    pub index: usize,
    /// Hash stored at this coordinate.
    pub digest: Digest,
}

/// Canonical complement proof for a sorted set of vector positions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MultiProof {
    /// Logical vector length to which the proof applies.
    pub len: usize,
    /// Authentication nodes sorted by `(level, index)`.
    pub nodes: Vec<ProofNode>,
}

/// Prover-side tree retained to support efficient openings and updates.
#[derive(Clone, Debug)]
pub struct MerkleTree {
    values: Vec<Bn254>,
    levels: Vec<Vec<Digest>>,
}

/// Merkle commitment or proof validation failure.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MerkleError {
    /// Vectors must contain at least one element.
    #[error("a committed vector must be non-empty")]
    EmptyVector,
    /// An opening position lies outside the logical vector.
    #[error("opening index {index} is outside vector length {len}")]
    IndexOutOfBounds {
        /// Invalid vector index.
        index: usize,
        /// Logical vector length.
        len: usize,
    },
    /// Opening indices must be strictly increasing and unique.
    #[error("opening indices must be strictly increasing")]
    NonCanonicalIndices,
    /// Values and indices do not have matching lengths.
    #[error("expected {expected} opened values, received {actual}")]
    ValueCountMismatch {
        /// Number of requested openings.
        expected: usize,
        /// Number of supplied values.
        actual: usize,
    },
    /// The proof has a non-canonical or incomplete node list.
    #[error("non-canonical Merkle multiproof")]
    NonCanonicalProof,
    /// The reconstructed root differs from the commitment.
    #[error("Merkle root mismatch")]
    RootMismatch,
}

impl MerkleTree {
    /// Commit to `values` and retain the full tree as auxiliary state.
    pub fn new(values: Vec<Bn254>) -> Result<Self, MerkleError> {
        if values.is_empty() {
            return Err(MerkleError::EmptyVector);
        }

        let padded_len = values.len().next_power_of_two();
        let mut leaves = Vec::with_capacity(padded_len);
        leaves.extend(
            values
                .iter()
                .copied()
                .enumerate()
                .map(|(i, value)| hash_leaf(i, value)),
        );
        leaves.extend((values.len()..padded_len).map(|i| hash_leaf(i, Bn254::ZERO)));

        let mut levels = vec![leaves];
        let mut level = 0;
        while levels[level].len() > 1 {
            let next = levels[level]
                .chunks_exact(2)
                .map(|children| hash_node(level, children[0], children[1]))
                .collect();
            levels.push(next);
            level += 1;
        }

        Ok(Self { values, levels })
    }

    /// Return the public commitment.
    #[must_use]
    pub fn commitment(&self) -> Commitment {
        Commitment {
            root: self.levels.last().expect("tree has a root")[0],
            len: self.values.len(),
        }
    }

    /// Return the committed values.
    pub fn values(&self) -> &[Bn254] {
        &self.values
    }

    /// Return one retained digest by `(level, index)` for protocol builders.
    pub(crate) fn digest_at(&self, level: usize, index: usize) -> Option<Digest> {
        self.levels
            .get(level)
            .and_then(|nodes| nodes.get(index))
            .copied()
    }

    /// Create the canonical complement proof for `indices`.
    pub fn open(&self, indices: &[usize]) -> Result<MultiProof, MerkleError> {
        validate_indices(indices, self.values.len())?;
        let coordinates = required_siblings(indices, self.levels.len() - 1);
        let nodes = coordinates
            .into_iter()
            .map(|(level, index)| ProofNode {
                level,
                index,
                digest: self.levels[level][index],
            })
            .collect();
        Ok(MultiProof {
            len: self.values.len(),
            nodes,
        })
    }

    /// Apply replacements and rebuild the sequential tree.
    pub fn update(&mut self, updates: &[(usize, Bn254)]) -> Result<(), MerkleError> {
        let indices: Vec<_> = updates.iter().map(|(index, _)| *index).collect();
        validate_indices(&indices, self.values.len())?;
        for &(index, value) in updates {
            self.values[index] = value;
        }
        *self = Self::new(self.values.clone())?;
        Ok(())
    }
}

/// Verify a canonical multiproof against the claimed values.
pub fn verify(
    commitment: Commitment,
    indices: &[usize],
    values: &[Bn254],
    proof: &MultiProof,
) -> Result<(), MerkleError> {
    validate_indices(indices, commitment.len)?;
    if values.len() != indices.len() {
        return Err(MerkleError::ValueCountMismatch {
            expected: indices.len(),
            actual: values.len(),
        });
    }
    if proof.len != commitment.len {
        return Err(MerkleError::NonCanonicalProof);
    }

    let height = commitment.len.next_power_of_two().trailing_zeros() as usize;
    let expected_coordinates = required_siblings(indices, height);
    if proof.nodes.len() != expected_coordinates.len()
        || proof
            .nodes
            .iter()
            .zip(&expected_coordinates)
            .any(|(node, &(level, index))| node.level != level || node.index != index)
    {
        return Err(MerkleError::NonCanonicalProof);
    }

    let proof_map: BTreeMap<_, _> = proof
        .nodes
        .iter()
        .map(|node| ((node.level, node.index), node.digest))
        .collect();
    let mut frontier: BTreeMap<usize, Digest> = indices
        .iter()
        .copied()
        .zip(values.iter().copied())
        .map(|(index, value)| (index, hash_leaf(index, value)))
        .collect();

    for level in 0..height {
        let current_indices: Vec<_> = frontier.keys().copied().collect();
        let mut next = BTreeMap::new();
        let mut consumed = BTreeSet::new();
        for index in current_indices {
            if consumed.contains(&index) {
                continue;
            }
            let sibling = index ^ 1;
            let here = frontier[&index];
            let sibling_digest = frontier
                .get(&sibling)
                .copied()
                .or_else(|| proof_map.get(&(level, sibling)).copied())
                .ok_or(MerkleError::NonCanonicalProof)?;
            let (left, right) = if index & 1 == 0 {
                (here, sibling_digest)
            } else {
                (sibling_digest, here)
            };
            next.insert(index >> 1, hash_node(level, left, right));
            consumed.insert(index);
            consumed.insert(sibling);
        }
        frontier = next;
    }

    if frontier.get(&0).copied() == Some(commitment.root) {
        Ok(())
    } else {
        Err(MerkleError::RootMismatch)
    }
}

fn validate_indices(indices: &[usize], len: usize) -> Result<(), MerkleError> {
    if indices.is_empty() || indices.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(MerkleError::NonCanonicalIndices);
    }
    if let Some(&index) = indices.iter().find(|&&index| index >= len) {
        return Err(MerkleError::IndexOutOfBounds { index, len });
    }
    Ok(())
}

fn required_siblings(indices: &[usize], height: usize) -> Vec<(usize, usize)> {
    let mut active: BTreeSet<usize> = indices.iter().copied().collect();
    let mut proof = Vec::new();
    for level in 0..height {
        let mut seen = BTreeSet::new();
        for &index in &active {
            let sibling = index ^ 1;
            if !active.contains(&sibling) && seen.insert(sibling) {
                proof.push((level, sibling));
            }
        }
        active = active.into_iter().map(|index| index >> 1).collect();
    }
    proof.sort_unstable();
    proof
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(n: usize) -> Vec<Bn254> {
        (0..n).map(Bn254::from_usize).collect()
    }

    #[test]
    fn multiproof_round_trip_and_tamper_rejection() {
        let tree = MerkleTree::new(values(7)).unwrap();
        let indices = [1, 2, 6];
        let opened = indices.map(|i| tree.values()[i]);
        let proof = tree.open(&indices).unwrap();
        verify(tree.commitment(), &indices, &opened, &proof).unwrap();

        let mut bad = opened;
        bad[1] += Bn254::ONE;
        assert_eq!(
            verify(tree.commitment(), &indices, &bad, &proof),
            Err(MerkleError::RootMismatch)
        );
    }

    #[test]
    fn complement_proof_is_reusable_for_exact_update_set() {
        let mut tree = MerkleTree::new(values(8)).unwrap();
        let indices = [2, 3];
        let old_values = indices.map(|i| tree.values()[i]);
        let proof = tree.open(&indices).unwrap();
        let old_commitment = tree.commitment();

        let new_values = [Bn254::from_u64(20), Bn254::from_u64(30)];
        tree.update(&[(2, new_values[0]), (3, new_values[1])])
            .unwrap();

        verify(old_commitment, &indices, &old_values, &proof).unwrap();
        verify(tree.commitment(), &indices, &new_values, &proof).unwrap();
    }

    #[test]
    fn verifier_rejects_noncanonical_and_incomplete_multiproofs() {
        let tree = MerkleTree::new(values(7)).unwrap();
        let commitment = tree.commitment();
        let indices = [1, 2, 6];
        let opened = indices.map(|index| tree.values()[index]);
        let proof = tree.open(&indices).unwrap();

        assert_eq!(
            verify(commitment, &[1, 1, 6], &opened, &proof),
            Err(MerkleError::NonCanonicalIndices)
        );
        assert_eq!(
            verify(commitment, &indices, &opened[..2], &proof),
            Err(MerkleError::ValueCountMismatch {
                expected: 3,
                actual: 2,
            })
        );

        let mut incomplete = proof.clone();
        incomplete.nodes.pop();
        assert_eq!(
            verify(commitment, &indices, &opened, &incomplete),
            Err(MerkleError::NonCanonicalProof)
        );

        let mut wrong_coordinate = proof.clone();
        wrong_coordinate.nodes[0].index ^= 1;
        assert_eq!(
            verify(commitment, &indices, &opened, &wrong_coordinate),
            Err(MerkleError::NonCanonicalProof)
        );

        let mut wrong_length = proof;
        wrong_length.len += 1;
        assert_eq!(
            verify(commitment, &indices, &opened, &wrong_length),
            Err(MerkleError::NonCanonicalProof)
        );
    }
}
