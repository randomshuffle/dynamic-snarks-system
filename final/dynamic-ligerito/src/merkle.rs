//! Canonical Poseidon2 Merkle vector commitments and reusable multiproofs.

use crate::parallel::prelude::*;
#[cfg(test)]
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::field::F;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::hash::{Digest, hash_leaf, hash_node};

#[cfg(test)]
thread_local! {
    static DENSE_CONSTRUCTIONS: Cell<usize> = const { Cell::new(0) };
}

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
    len: usize,
    height: usize,
    storage: Arc<TreeStorage>,
}

/// Dense indexed trees are constructed once. Updates retain their parent and
/// store only the changed values and the union of changed authentication paths.
#[derive(Debug)]
enum TreeStorage {
    Dense {
        values: Vec<F>,
        levels: Vec<Vec<Digest>>,
    },
    Overlay {
        parent: Arc<TreeStorage>,
        values: BTreeMap<usize, F>,
        digests: BTreeMap<(usize, usize), Digest>,
    },
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
    pub fn new(values: Vec<F>) -> Result<Self, MerkleError> {
        if values.is_empty() {
            return Err(MerkleError::EmptyVector);
        }
        #[cfg(test)]
        DENSE_CONSTRUCTIONS.with(|count| count.set(count.get() + 1));

        let padded_len = values.len().next_power_of_two();
        let leaves = (0..padded_len)
            .into_par_iter()
            .map(|index| hash_leaf(index, values.get(index).copied().unwrap_or(F::ZERO)))
            .collect::<Vec<_>>();

        let mut levels = vec![leaves];
        let mut level = 0;
        while levels[level].len() > 1 {
            let next = levels[level]
                .par_chunks_exact(2)
                .map(|children| hash_node(level, children[0], children[1]))
                .collect();
            levels.push(next);
            level += 1;
        }

        Ok(Self {
            len: values.len(),
            height: padded_len.trailing_zeros() as usize,
            storage: Arc::new(TreeStorage::Dense { values, levels }),
        })
    }

    /// Return the public commitment.
    #[must_use]
    pub fn commitment(&self) -> Commitment {
        Commitment {
            root: self
                .digest_at(self.height, 0)
                .expect("a retained Merkle tree has a root"),
            len: self.len,
        }
    }

    /// Return one committed vector value by position.
    pub fn value(&self, index: usize) -> Option<F> {
        (index < self.len)
            .then(|| storage_value(&self.storage, index))
            .flatten()
    }

    /// Return one retained digest by `(level, index)` for protocol builders.
    pub(crate) fn digest_at(&self, level: usize, index: usize) -> Option<Digest> {
        if level > self.height || index >= (1usize << (self.height - level)) {
            return None;
        }
        storage_digest(&self.storage, level, index)
    }

    /// Create the canonical complement proof for `indices`.
    pub fn open(&self, indices: &[usize]) -> Result<MultiProof, MerkleError> {
        validate_indices(indices, self.len)?;
        let coordinates = required_siblings(indices, self.height);
        let nodes = coordinates
            .into_iter()
            .map(|(level, index)| ProofNode {
                level,
                index,
                digest: self
                    .digest_at(level, index)
                    .expect("a canonical proof coordinate is retained"),
            })
            .collect();
        Ok(MultiProof {
            len: self.len,
            nodes,
        })
    }

    /// Return a new tree after recomputing only the union of changed paths.
    pub fn updated(&self, updates: &[(usize, F)]) -> Result<Self, MerkleError> {
        let indices = updates.iter().map(|(index, _)| *index).collect::<Vec<_>>();
        validate_indices(&indices, self.len)?;

        let values = updates.iter().copied().collect::<BTreeMap<_, _>>();
        let mut digests = updates
            .iter()
            .map(|&(index, value)| ((0, index), hash_leaf(index, value)))
            .collect::<BTreeMap<_, _>>();
        let mut active = indices.into_iter().collect::<BTreeSet<_>>();
        for level in 0..self.height {
            let parents = active
                .iter()
                .map(|index| index >> 1)
                .collect::<BTreeSet<_>>();
            let parent_list = parents.iter().copied().collect::<Vec<_>>();
            let next = parent_list
                .into_par_iter()
                .map(|parent| {
                    let left_index = 2 * parent;
                    let right_index = left_index + 1;
                    let left = digests
                        .get(&(level, left_index))
                        .copied()
                        .or_else(|| self.digest_at(level, left_index))
                        .expect("an affected parent has a retained left child");
                    let right = digests
                        .get(&(level, right_index))
                        .copied()
                        .or_else(|| self.digest_at(level, right_index))
                        .expect("an affected parent has a retained right child");
                    ((level + 1, parent), hash_node(level, left, right))
                })
                .collect::<Vec<_>>();
            digests.extend(next);
            active = parents;
        }

        Ok(Self {
            len: self.len,
            height: self.height,
            storage: Arc::new(TreeStorage::Overlay {
                parent: Arc::clone(&self.storage),
                values,
                digests,
            }),
        })
    }

    /// Apply replacements by installing a path-local persistent update.
    pub fn update(&mut self, updates: &[(usize, F)]) -> Result<(), MerkleError> {
        *self = self.updated(updates)?;
        Ok(())
    }

    /// Refresh only authentication nodes whose subtrees contain an update.
    /// The opened index set is fixed, so no scan over it is required.
    pub(crate) fn refresh_opening(
        &self,
        proof: &mut MultiProof,
        changed_indices: &[usize],
    ) -> Result<(), MerkleError> {
        validate_indices(changed_indices, self.len)?;
        if proof.len != self.len {
            return Err(MerkleError::NonCanonicalProof);
        }
        for &changed in changed_indices {
            for level in 0..self.height {
                let coordinate = (level, changed >> level);
                if let Ok(position) = proof
                    .nodes
                    .binary_search_by_key(&coordinate, |node| (node.level, node.index))
                {
                    proof.nodes[position].digest = self
                        .digest_at(coordinate.0, coordinate.1)
                        .expect("an updated proof coordinate is retained");
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) fn reset_dense_construction_count() {
    DENSE_CONSTRUCTIONS.with(|count| count.set(0));
}

#[cfg(test)]
pub(crate) fn dense_construction_count() -> usize {
    DENSE_CONSTRUCTIONS.with(Cell::get)
}

fn storage_value(storage: &TreeStorage, index: usize) -> Option<F> {
    match storage {
        TreeStorage::Dense { values, .. } => values.get(index).copied(),
        TreeStorage::Overlay { parent, values, .. } => values
            .get(&index)
            .copied()
            .or_else(|| storage_value(parent, index)),
    }
}

fn storage_digest(storage: &TreeStorage, level: usize, index: usize) -> Option<Digest> {
    match storage {
        TreeStorage::Dense { levels, .. } => levels
            .get(level)
            .and_then(|nodes| nodes.get(index))
            .copied(),
        TreeStorage::Overlay {
            parent, digests, ..
        } => digests
            .get(&(level, index))
            .copied()
            .or_else(|| storage_digest(parent, level, index)),
    }
}

/// Verify a canonical multiproof against the claimed values.
pub fn verify(
    commitment: Commitment,
    indices: &[usize],
    values: &[F],
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

pub(crate) fn required_siblings(indices: &[usize], height: usize) -> Vec<(usize, usize)> {
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
