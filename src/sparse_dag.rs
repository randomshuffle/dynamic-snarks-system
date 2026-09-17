//! Canonical sparse Merkle authentication DAGs used by transition proofs.

use p3_maybe_rayon::prelude::*;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};

use p3_bn254::Bn254;
use p3_field::PrimeCharacteristicRing;
use thiserror::Error;

use crate::hash::{Digest, hash_leaf, hash_node};
use crate::merkle::{Commitment, MerkleError, MerkleTree};

/// Domain tag separating independently routed Merkle computations.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum TreeId {
    Assignment = 1,
    Permutation = 2,
    Neighbor = 3,
}

/// One coordinate in a padded binary Merkle tree.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct Coordinate {
    pub(crate) level: usize,
    pub(crate) index: usize,
}

/// How a sparse authentication node obtains its digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NodeKind {
    /// An explicitly queried vector position.
    Leaf,
    /// A supplied digest for a subtree disjoint from all queries.
    Boundary,
    /// A node recomputed from its two child rows.
    Internal,
}

/// The old/new digest pair carried by one routed node.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DigestPair {
    pub(crate) old: Digest,
    pub(crate) new: Digest,
}

/// One canonical sparse-DAG row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NodeRow {
    pub(crate) tree: TreeId,
    pub(crate) coordinate: Coordinate,
    pub(crate) kind: NodeKind,
    pub(crate) digest: DigestPair,
    pub(crate) children: Option<[DigestPair; 2]>,
    pub(crate) leaf_values: Option<[Bn254; 2]>,
}

/// A producer or child-reference tuple before Fiat--Shamir compression.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RouteTuple {
    pub(crate) tree: TreeId,
    pub(crate) coordinate: Coordinate,
    pub(crate) digest: DigestPair,
}

impl RouteTuple {
    /// Fixed field encoding used later by the routing multiset argument.
    pub(crate) fn fields(self) -> [Bn254; 6] {
        [
            Bn254::ONE,
            Bn254::from_u64(self.tree as u64),
            Bn254::from_usize(self.coordinate.level),
            Bn254::from_usize(self.coordinate.index),
            self.digest.old,
            self.digest.new,
        ]
    }
}

/// Canonical union of queried paths and their complement nodes.
#[derive(Clone, Debug)]
pub(crate) struct SparseMerkleDag {
    tree: TreeId,
    height: usize,
    old_commitment: Commitment,
    new_commitment: Commitment,
    rows: Vec<NodeRow>,
}

/// Fixed-width committed representation of several sparse-DAG routings.
/// Each row contains one six-field producer tuple, one six-field reference
/// tuple, and four zero padding fields, making the flattened table a
/// power-of-two MLE evaluation vector.
#[derive(Clone, Debug)]
pub(crate) struct RoutingTable {
    producers: Vec<RouteTuple>,
    references: Vec<RouteTuple>,
    row_count: usize,
}

impl RoutingTable {
    pub(crate) fn from_dags(dags: &[SparseMerkleDag]) -> Result<Self, Error> {
        let producers = dags
            .iter()
            .flat_map(SparseMerkleDag::producers)
            .collect::<Vec<_>>();
        let references = dags
            .iter()
            .flat_map(SparseMerkleDag::references)
            .collect::<Vec<_>>();
        if !route_multisets_match(&producers, &references) {
            return Err(Error::Routing);
        }
        let row_count = producers.len().max(2).next_power_of_two();
        Ok(Self {
            producers,
            references,
            row_count,
        })
    }

    pub(crate) const fn row_count(&self) -> usize {
        self.row_count
    }

    pub(crate) fn producers(&self) -> &[RouteTuple] {
        &self.producers
    }

    pub(crate) fn references(&self) -> &[RouteTuple] {
        &self.references
    }

    /// Row-major, width-16 evaluation table. A zero first field distinguishes
    /// padding from every real route tuple.
    pub(crate) fn evaluations(&self) -> Vec<Bn254> {
        let mut evaluations = Vec::with_capacity(16 * self.row_count);
        for row in 0..self.row_count {
            evaluations.extend(
                self.producers
                    .get(row)
                    .copied()
                    .map_or([Bn254::ZERO; 6], RouteTuple::fields),
            );
            evaluations.extend(
                self.references
                    .get(row)
                    .copied()
                    .map_or([Bn254::ZERO; 6], RouteTuple::fields),
            );
            evaluations.extend([Bn254::ZERO; 4]);
        }
        evaluations
    }
}

/// Invalid sparse authentication data.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub(crate) enum Error {
    #[error(transparent)]
    Merkle(#[from] MerkleError),
    #[error("old and new sparse-DAG trees have different logical lengths")]
    Length,
    #[error("new tree changes a complement subtree outside the query set")]
    ChangedBoundary,
    #[error("sparse-DAG row set is incomplete or noncanonical")]
    NonCanonical,
    #[error("sparse-DAG local hash relation failed")]
    Hash,
    #[error("sparse-DAG producer/reference routing failed")]
    Routing,
    #[error("sparse-DAG root does not match its public commitment")]
    Root,
}

impl SparseMerkleDag {
    /// Count all rows and non-boundary hashes from path coordinates alone.
    /// This performs no dense allocation or hashing, even for a very large tree.
    pub(crate) fn shape(tree_len: usize, indices: &[usize]) -> Result<(usize, usize), Error> {
        if tree_len == 0
            || indices.is_empty()
            || indices.windows(2).any(|pair| pair[0] >= pair[1])
            || indices.iter().any(|&index| index >= tree_len)
        {
            return Err(Error::NonCanonical);
        }
        let height = tree_len.next_power_of_two().trailing_zeros();
        let mut active = indices.iter().copied().collect::<BTreeSet<_>>();
        let mut rows = active.len();
        let mut hashes = active.len();
        for _ in 0..height {
            rows += active
                .iter()
                .filter(|&&index| !active.contains(&(index ^ 1)))
                .count();
            active = active.into_iter().map(|index| index >> 1).collect();
            rows += active.len();
            hashes += active.len();
        }
        Ok((rows, hashes))
    }

    /// Build a paired old/new authentication DAG. Complement nodes must be
    /// identical, so the two vectors can differ only at `indices`.
    pub(crate) fn paired(
        tree: TreeId,
        old: &MerkleTree,
        new: &MerkleTree,
        indices: &[usize],
    ) -> Result<Self, Error> {
        if old.commitment().len != new.commitment().len {
            return Err(Error::Length);
        }
        let proof = old.open(indices)?;
        let proof_coordinates = proof
            .nodes
            .iter()
            .map(|node| Coordinate {
                level: node.level,
                index: node.index,
            })
            .collect::<BTreeSet<_>>();
        let height = old.commitment().len.next_power_of_two().trailing_zeros() as usize;
        let mut coordinates = proof_coordinates.clone();
        for &index in indices {
            coordinates.insert(Coordinate { level: 0, index });
            for level in 1..=height {
                coordinates.insert(Coordinate {
                    level,
                    index: index >> level,
                });
            }
        }

        let query_set = indices.iter().copied().collect::<BTreeSet<_>>();
        let mut rows = Vec::with_capacity(coordinates.len());
        for coordinate in coordinates {
            let old_digest = old
                .digest_at(coordinate.level, coordinate.index)
                .ok_or(Error::NonCanonical)?;
            let new_digest = new
                .digest_at(coordinate.level, coordinate.index)
                .ok_or(Error::NonCanonical)?;
            let kind = if proof_coordinates.contains(&coordinate) {
                if old_digest != new_digest {
                    return Err(Error::ChangedBoundary);
                }
                NodeKind::Boundary
            } else if coordinate.level == 0 {
                if !query_set.contains(&coordinate.index) {
                    return Err(Error::NonCanonical);
                }
                NodeKind::Leaf
            } else {
                NodeKind::Internal
            };
            let children = (kind == NodeKind::Internal)
                .then(|| -> Result<[DigestPair; 2], Error> {
                    let child_level = coordinate.level - 1;
                    Ok([
                        DigestPair {
                            old: old
                                .digest_at(child_level, 2 * coordinate.index)
                                .ok_or(Error::NonCanonical)?,
                            new: new
                                .digest_at(child_level, 2 * coordinate.index)
                                .ok_or(Error::NonCanonical)?,
                        },
                        DigestPair {
                            old: old
                                .digest_at(child_level, 2 * coordinate.index + 1)
                                .ok_or(Error::NonCanonical)?,
                            new: new
                                .digest_at(child_level, 2 * coordinate.index + 1)
                                .ok_or(Error::NonCanonical)?,
                        },
                    ])
                })
                .transpose()?;
            let leaf_values = (kind == NodeKind::Leaf).then(|| {
                [
                    old.value(coordinate.index)
                        .expect("a sparse leaf is within the old tree"),
                    new.value(coordinate.index)
                        .expect("a sparse leaf is within the new tree"),
                ]
            });
            rows.push(NodeRow {
                tree,
                coordinate,
                kind,
                digest: DigestPair {
                    old: old_digest,
                    new: new_digest,
                },
                children,
                leaf_values,
            });
        }
        // Roots first, followed by a deterministic level-major ordering.
        rows.sort_by_key(|row| (Reverse(row.coordinate.level), row.coordinate.index));
        let dag = Self {
            tree,
            height,
            old_commitment: old.commitment(),
            new_commitment: new.commitment(),
            rows,
        };
        dag.validate()?;
        Ok(dag)
    }

    /// Build an ordinary single-tree opening using identical old/new digest
    /// columns. Keeping one row format lets all transition DAGs share one
    /// routing product.
    pub(crate) fn single(
        tree: TreeId,
        merkle: &MerkleTree,
        indices: &[usize],
    ) -> Result<Self, Error> {
        Self::paired(tree, merkle, merkle, indices)
    }

    pub(crate) fn rows(&self) -> &[NodeRow] {
        &self.rows
    }

    pub(crate) fn root(&self) -> DigestPair {
        self.rows[0].digest
    }

    /// One tuple for every non-root node.
    pub(crate) fn producers(&self) -> Vec<RouteTuple> {
        self.rows
            .iter()
            .skip(1)
            .map(|row| RouteTuple {
                tree: row.tree,
                coordinate: row.coordinate,
                digest: row.digest,
            })
            .collect()
    }

    /// Two tuple references for every internal node.
    pub(crate) fn references(&self) -> Vec<RouteTuple> {
        self.rows
            .iter()
            .filter_map(|row| row.children.map(|children| (row, children)))
            .flat_map(|(row, children)| {
                let child_level = row.coordinate.level - 1;
                [
                    RouteTuple {
                        tree: row.tree,
                        coordinate: Coordinate {
                            level: child_level,
                            index: 2 * row.coordinate.index,
                        },
                        digest: children[0],
                    },
                    RouteTuple {
                        tree: row.tree,
                        coordinate: Coordinate {
                            level: child_level,
                            index: 2 * row.coordinate.index + 1,
                        },
                        digest: children[1],
                    },
                ]
            })
            .collect()
    }

    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.rows.is_empty()
            || self.rows[0].tree != self.tree
            || self.rows[0].coordinate
                != (Coordinate {
                    level: self.height,
                    index: 0,
                })
            || self.rows.windows(2).any(|rows| {
                (Reverse(rows[0].coordinate.level), rows[0].coordinate.index)
                    >= (Reverse(rows[1].coordinate.level), rows[1].coordinate.index)
            })
        {
            return Err(Error::NonCanonical);
        }

        self.rows
            .par_iter()
            .map(|row| {
                match row.kind {
                    NodeKind::Leaf => {
                        let [old, new] = row.leaf_values.ok_or(Error::NonCanonical)?;
                        if row.coordinate.level != 0
                            || row.children.is_some()
                            || row.digest.old != hash_leaf(row.coordinate.index, old)
                            || row.digest.new != hash_leaf(row.coordinate.index, new)
                        {
                            return Err(Error::Hash);
                        }
                    }
                    NodeKind::Boundary => {
                        if row.children.is_some()
                            || row.leaf_values.is_some()
                            || row.digest.old != row.digest.new
                        {
                            return Err(Error::ChangedBoundary);
                        }
                    }
                    NodeKind::Internal => {
                        let [left, right] = row.children.ok_or(Error::NonCanonical)?;
                        if row.coordinate.level == 0
                            || row.leaf_values.is_some()
                            || row.digest.old
                                != hash_node(row.coordinate.level - 1, left.old, right.old)
                            || row.digest.new
                                != hash_node(row.coordinate.level - 1, left.new, right.new)
                        {
                            return Err(Error::Hash);
                        }
                    }
                }
                Ok(())
            })
            .collect::<Vec<Result<(), Error>>>()
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;
        if self.root().old != self.old_commitment.root
            || self.root().new != self.new_commitment.root
        {
            return Err(Error::Root);
        }
        if !route_multisets_match(&self.producers(), &self.references()) {
            return Err(Error::Routing);
        }
        Ok(())
    }
}

fn route_multisets_match(producers: &[RouteTuple], references: &[RouteTuple]) -> bool {
    if producers.len() != references.len() {
        return false;
    }
    let mut producer_map = BTreeMap::<(TreeId, Coordinate), Vec<DigestPair>>::new();
    let mut reference_map = BTreeMap::<(TreeId, Coordinate), Vec<DigestPair>>::new();
    for tuple in producers {
        producer_map
            .entry((tuple.tree, tuple.coordinate))
            .or_default()
            .push(tuple.digest);
    }
    for tuple in references {
        reference_map
            .entry((tuple.tree, tuple.coordinate))
            .or_default()
            .push(tuple.digest);
    }
    producer_map == reference_map
}

#[cfg(test)]
mod tests {
    #[test]
    fn coordinate_only_shape_matches_materialized_dags() {
        for length in [1, 7, 16, 31] {
            let tree =
                super::MerkleTree::new((0..length).map(p3_bn254::Bn254::from_usize).collect())
                    .unwrap();
            for indices in [
                vec![0],
                vec![length - 1],
                (0..length).step_by(3).collect(),
                (0..length).collect(),
            ] {
                let dag =
                    super::SparseMerkleDag::single(super::TreeId::Assignment, &tree, &indices)
                        .unwrap();
                let hashes = dag
                    .rows()
                    .iter()
                    .filter(|row| row.kind != super::NodeKind::Boundary)
                    .count();
                assert_eq!(
                    super::SparseMerkleDag::shape(length, &indices).unwrap(),
                    (dag.rows().len(), hashes)
                );
            }
        }
        assert!(super::SparseMerkleDag::shape(16, &[3, 3]).is_err());
        assert!(super::SparseMerkleDag::shape(16, &[16]).is_err());
        // A 2^26-leaf tree must be shape-checkable without building that tree.
        assert_eq!(
            super::SparseMerkleDag::shape(1 << 26, &[0]).unwrap(),
            (53, 27)
        );
    }

    use crate::static_snark::commit_mle;

    use super::*;

    fn values(len: usize, offset: usize) -> Vec<Bn254> {
        (0..len)
            .map(|index| Bn254::from_usize(index + offset))
            .collect()
    }

    #[test]
    fn paired_dag_reconstructs_both_roots_and_routes_every_node() {
        let old = MerkleTree::new(values(13, 1)).unwrap();
        let mut new = old.clone();
        new.update(&[(1, Bn254::from_u64(91)), (9, Bn254::from_u64(99))])
            .unwrap();
        let dag = SparseMerkleDag::paired(TreeId::Assignment, &old, &new, &[1, 9]).unwrap();
        assert_eq!(dag.root().old, old.commitment().root);
        assert_eq!(dag.root().new, new.commitment().root);
        assert_eq!(dag.producers().len(), dag.references().len());
        assert!(route_multisets_match(&dag.producers(), &dag.references()));
        assert!(
            dag.rows()
                .iter()
                .filter(|row| row.kind == NodeKind::Boundary)
                .all(|row| row.digest.old == row.digest.new)
        );
    }

    #[test]
    fn non_power_of_two_and_public_suffix_query_are_canonical() {
        let tree = MerkleTree::new(values(19, 7)).unwrap();
        let indices = [0, 17, 18];
        let first = SparseMerkleDag::single(TreeId::Neighbor, &tree, &indices).unwrap();
        let second = SparseMerkleDag::single(TreeId::Neighbor, &tree, &indices).unwrap();
        assert_eq!(first.rows(), second.rows());
        assert_eq!(first.root().new, tree.commitment().root);
        first.validate().unwrap();
    }

    #[test]
    fn changed_complement_and_tampered_routing_are_rejected() {
        let old = MerkleTree::new(values(16, 1)).unwrap();
        let mut changed_outside_query = old.clone();
        changed_outside_query
            .update(&[(14, Bn254::from_u64(44))])
            .unwrap();
        assert_eq!(
            SparseMerkleDag::paired(TreeId::Assignment, &old, &changed_outside_query, &[2])
                .unwrap_err(),
            Error::ChangedBoundary
        );

        let mut updated = old.clone();
        updated.update(&[(2, Bn254::from_u64(77))]).unwrap();
        let mut dag = SparseMerkleDag::paired(TreeId::Assignment, &old, &updated, &[2]).unwrap();
        let internal = dag
            .rows
            .iter_mut()
            .find(|row| row.kind == NodeKind::Internal)
            .unwrap();
        internal.children.as_mut().unwrap()[0].old += Bn254::ONE;
        assert!(matches!(dag.validate(), Err(Error::Hash | Error::Routing)));
    }

    #[test]
    fn combined_route_table_has_a_power_of_two_commitment_layout() {
        let old = MerkleTree::new(values(21, 1)).unwrap();
        let mut new = old.clone();
        new.update(&[(2, Bn254::from_u64(72)), (18, Bn254::from_u64(88))])
            .unwrap();
        let assignment = SparseMerkleDag::paired(TreeId::Assignment, &old, &new, &[2, 18]).unwrap();

        let permutation_values = (0..21).rev().map(Bn254::from_usize).collect::<Vec<_>>();
        let permutation_tree = MerkleTree::new(permutation_values).unwrap();
        let permutation =
            SparseMerkleDag::single(TreeId::Permutation, &permutation_tree, &[2, 18]).unwrap();
        let neighbor = SparseMerkleDag::single(TreeId::Neighbor, &new, &[2, 18]).unwrap();
        let table = RoutingTable::from_dags(&[assignment, permutation, neighbor]).unwrap();
        assert!(table.row_count().is_power_of_two());
        assert_eq!(table.producers().len(), table.references().len());
        let evaluations = table.evaluations();
        assert_eq!(evaluations.len(), 16 * table.row_count());
        assert!(evaluations.len().is_power_of_two());
        let committed = commit_mle(evaluations).unwrap();
        assert!(!committed.commitment().roots().is_empty());
    }
}
